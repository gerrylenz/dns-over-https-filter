use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use serde::{Deserialize, Serialize};
use socket2::{Domain as SocketFamily, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::config::{self, build_filter, BlocklistConfig, Settings};
use crate::filter::{classify, Domain, Filter, Local};
use crate::http;
use crate::lists;
use crate::tls;
use crate::upstream::Pool;

pub async fn serve() -> Result<(), String> {
    tls::install_provider();
    let config_path = config::config_path_from_args();
    let mut settings = Settings::load(&config_path)?;
    let directory = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let (cert, key) = tls::ensure(&mut settings, &directory)?;
    settings.save(&config_path)?;
    let tls_config = tls::server_config(&cert.0, &key.0)?;

    let app = Arc::new(App::new(config_path, directory, settings));
    app.load_history();
    app.load_lists();
    app.rebuild_filter();
    app.replace_pool().await;

    let admin = parse_addr(&app.settings.load().admin_listen)?;
    let dns = parse_addr(&app.settings.load().dns_listen)?;
    let doh = parse_addr(&app.settings.load().doh_listen)?;
    app.bound.lock().unwrap().clone_from(&Bound { dns, doh, admin });

    let admin_listener = bind_tcp(admin).map_err(|error| {
        format!("Oberfläche auf {admin} ist nicht frei: {error}")
    })?;
    match bind_udp(dns) {
        Ok(socket) => {
            spawn_udp(socket, app.clone());
            app.dns_up.store(true, Ordering::Relaxed);
        }
        Err(error) => app.errors.lock().unwrap().push(format!("DNS auf {dns} ist nicht frei: {error}")),
    }
    match bind_tcp(dns) {
        Ok(listener) => spawn_tcp(listener, app.clone()),
        Err(error) => app.errors.lock().unwrap().push(format!("DNS-TCP auf {dns} ist nicht frei: {error}")),
    }
    match bind_tcp(doh) {
        Ok(listener) => {
            http::spawn_doh(listener, tls_config, app.clone());
            app.doh_up.store(true, Ordering::Relaxed);
        }
        Err(error) => app.errors.lock().unwrap().push(format!("DoH auf {doh} ist nicht frei: {error}")),
    }
    http::spawn_admin(admin_listener, app.clone());

    let history = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            history.flush_history();
        }
    });

    let refresher = app.clone();
    tokio::spawn(async move {
        loop {
            refresher.refresh_once().await;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(6 * 60 * 60)) => {}
                _ = refresher.refresh.notified() => {}
            }
        }
    });

    let address = server_ip();
    println!("Oberfläche: http://{admin}/");
    println!("DNS: {dns}  (nur localhost und eingetragene Router)");
    println!("DoH: Port {}. Die Adresse mit Token steht in der Oberfläche.", doh.port());
    println!("Serveradresse für den statischen Eintrag: {address}");
    for error in app.errors.lock().unwrap().iter() {
        println!("{error}");
    }
    tokio::signal::ctrl_c().await.ok();
    println!("\nBeendet.");
    Ok(())
}

struct Bound {
    dns: SocketAddr,
    doh: SocketAddr,
    admin: SocketAddr,
}

impl Clone for Bound {
    fn clone(&self) -> Self {
        Self { dns: self.dns, doh: self.doh, admin: self.admin }
    }
}

struct ListMeta {
    domains: usize,
    updated: Option<String>,
    error: Option<String>,
}

struct Lists {
    domains: HashMap<String, Vec<String>>,
    meta: HashMap<String, ListMeta>,
}

struct CacheEntry {
    expires: Instant,
    stale_until: Instant,
    message: Message,
}

struct LogLine {
    time: String,
    client: String,
    name: String,
    qtype: String,
    action: &'static str,
    ms: u128,
}

#[derive(Clone, Serialize, Deserialize)]
struct DayRoll {
    date: String,
    #[serde(default)]
    total: u64,
    #[serde(default)]
    blocked: u64,
    #[serde(default)]
    cached: u64,
    #[serde(default)]
    rewritten: u64,
    #[serde(default)]
    failed: u64,
    #[serde(default)]
    names: HashMap<String, u64>,
    #[serde(default)]
    blocked_names: HashMap<String, u64>,
}

struct Journal {
    lines: VecDeque<LogLine>,
    days: Vec<DayRoll>,
    dirty: bool,
}

struct Counters {
    total: AtomicU64,
    blocked: AtomicU64,
    cached: AtomicU64,
    rewritten: AtomicU64,
    failed: AtomicU64,
}

struct Flight {
    inflight: Mutex<HashMap<String, watch::Sender<Option<Result<Message, ()>>>>>,
}

pub struct App {
    config_path: PathBuf,
    directory: PathBuf,
    settings: ArcSwap<Settings>,
    filter: ArcSwap<Filter>,
    lists: Mutex<Lists>,
    pool: ArcSwap<Pool>,
    cache: Mutex<HashMap<String, CacheEntry>>,
    flight: Flight,
    journal: Mutex<Journal>,
    counters: Counters,
    refresh: tokio::sync::Notify,
    bound: Mutex<Bound>,
    dns_up: AtomicBool,
    doh_up: AtomicBool,
    errors: Mutex<Vec<String>>,
    rates: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl App {
    fn new(config_path: PathBuf, directory: PathBuf, settings: Settings) -> Self {
        Self {
            config_path,
            directory,
            settings: ArcSwap::from_pointee(settings),
            filter: ArcSwap::from_pointee(Filter::default()),
            lists: Mutex::new(Lists { domains: HashMap::new(), meta: HashMap::new() }),
            pool: ArcSwap::from(Pool::empty()),
            cache: Mutex::new(HashMap::new()),
            flight: Flight { inflight: Mutex::new(HashMap::new()) },
            journal: Mutex::new(Journal {
                lines: VecDeque::with_capacity(256),
                days: Vec::new(),
                dirty: false,
            }),
            counters: Counters {
                total: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
                cached: AtomicU64::new(0),
                rewritten: AtomicU64::new(0),
                failed: AtomicU64::new(0),
            },
            refresh: tokio::sync::Notify::new(),
            bound: Mutex::new(Bound {
                dns: "127.0.0.1:0".parse().unwrap(),
                doh: "127.0.0.1:0".parse().unwrap(),
                admin: "127.0.0.1:0".parse().unwrap(),
            }),
            dns_up: AtomicBool::new(false),
            doh_up: AtomicBool::new(false),
            errors: Mutex::new(Vec::new()),
            rates: Mutex::new(HashMap::new()),
        }
    }

    fn load_lists(&self) {
        let settings = self.settings.load();
        let mut lists = self.lists.lock().unwrap();
        for item in &settings.blocklists {
            let path = self.directory.join("lists").join(format!("{}.domains", item.id));
            let domains: Vec<String> = lists::load_file(&path).into_iter().collect();
            lists.meta.insert(item.id.clone(), ListMeta {
                domains: domains.len(),
                updated: None,
                error: None,
            });
            lists.domains.insert(item.id.clone(), domains);
        }
    }

    fn rebuild_filter(&self) {
        let settings = self.settings.load();
        let lists = self.lists.lock().unwrap();
        let input: Vec<_> = settings
            .blocklists
            .iter()
            .map(|item| {
                let domains = lists.domains.get(&item.id).cloned().unwrap_or_default();
                (item.id.clone(), item.enabled, domains)
            })
            .collect();
        drop(lists);
        self.filter.store(Arc::new(build_filter(&settings, &input)));
    }

    async fn replace_pool(&self) {
        let addresses: Vec<SocketAddr> = self
            .settings
            .load()
            .upstreams
            .iter()
            .filter_map(|item| item.parse().ok())
            .collect();
        self.pool.store(Pool::start(&addresses).await);
    }

    pub fn ask_refresh(&self) {
        self.refresh.notify_one();
    }

    async fn refresh_once(&self) {
        let items = self.settings.load().blocklists.clone();
        for item in items {
            if !item.enabled || !config::valid_id(&item.id) {
                continue;
            }
            let url = item.url.clone();
            let loaded = tokio::task::spawn_blocking(move || lists::download(&url)).await;
            let mut lists = self.lists.lock().unwrap();
            match loaded {
                Ok(Ok(text)) => {
                    let domains = lists::extract(&text);
                    let path = self.directory.join("lists").join(format!("{}.domains", item.id));
                    let previous_update = lists.meta.get(&item.id).and_then(|meta| meta.updated.clone());
                    if let Err(error) = lists::save_file(&path, &domains) {
                        lists.meta.insert(item.id.clone(), ListMeta {
                            domains: domains.len(),
                            updated: previous_update,
                            error: Some(error.to_string()),
                        });
                    } else {
                        lists.meta.insert(item.id.clone(), ListMeta {
                            domains: domains.len(),
                            updated: Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()),
                            error: None,
                        });
                    }
                    lists.domains.insert(item.id, domains.into_iter().collect());
                }
                Ok(Err(error)) => note_error(&mut lists, &item, error),
                Err(_) => note_error(&mut lists, &item, "Liste konnte nicht geladen werden.".into()),
            }
            drop(lists);
            self.rebuild_filter();
        }
    }

    pub async fn update_config(&self, patch: serde_json::Value) -> Result<(), String> {
        let object = patch.as_object().ok_or("Einstellungen sind ungültig.")?;
        let mut settings = (*self.settings.load_full()).clone();
        let previous_upstreams = settings.upstreams.clone();
        apply_patch(&mut settings, object)?;
        settings.normalize();
        settings.save(&self.config_path)?;
        let upstreams_changed = settings.upstreams != previous_upstreams;
        self.settings.store(Arc::new(settings));
        self.rebuild_filter();
        if upstreams_changed {
            self.replace_pool().await;
        }
        Ok(())
    }

    pub fn rotate_token(&self) -> Result<String, String> {
        let mut settings = (*self.settings.load_full()).clone();
        settings.doh_token = config::new_token();
        let token = settings.doh_token.clone();
        settings.save(&self.config_path)?;
        self.settings.store(Arc::new(settings));
        Ok(token)
    }

    pub fn token_matches(&self, path: &str) -> bool {
        let token = self.settings.load().doh_token.clone();
        let given = path.trim_start_matches('/');
        if given.len() != token.len() {
            return false;
        }
        use subtle::ConstantTimeEq;
        given.as_bytes().ct_eq(token.as_bytes()).into()
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let settings = self.settings.load();
        let lists = self.lists.lock().unwrap();
        let blocklists: Vec<ListView> = settings
            .blocklists
            .iter()
            .map(|item| {
                let meta = lists.meta.get(&item.id);
                ListView {
                    id: item.id.clone(),
                    name: item.name.clone(),
                    url: item.url.clone(),
                    enabled: item.enabled,
                    domains: meta.map(|meta| meta.domains).unwrap_or(0),
                    updated: meta.and_then(|meta| meta.updated.clone()),
                    error: meta.and_then(|meta| meta.error.clone()),
                }
            })
            .collect();
        let blocked_domains = self.filter.load().block.len();
        let journal = self.journal.lock().unwrap();
        let (week, days) = week_view(&journal.days);
        let log: Vec<LogView> = journal.lines.iter().rev().take(80).collect::<Vec<_>>().into_iter().rev().map(|line| LogView {
            time: line.time.clone(),
            client: line.client.clone(),
            name: line.name.clone(),
            r#type: line.qtype.clone(),
            action: line.action,
            ms: line.ms,
        }).collect();
        drop(journal);
        let bound = self.bound.lock().unwrap().clone();
        let restart = settings.dns_listen != bound.dns.to_string()
            || settings.doh_listen != bound.doh.to_string()
            || settings.admin_listen != bound.admin.to_string()
            || (settings.self_signed && settings.cert_hostname != settings.hostname);
        let server_ip = server_ip();
        let doh_port = bound.doh.port();
        let view = StateView {
            running: self.dns_up.load(Ordering::Relaxed) || self.doh_up.load(Ordering::Relaxed),
            error: {
                let text = self.errors.lock().unwrap().join(" ");
                text
            },
            blocked_domains,
            server_ip: server_ip.clone(),
            doh_url: config::doh_url(&settings.hostname, doh_port, &settings.doh_token),
            restart_required: restart,
            routeros: config::routeros(&settings.hostname, doh_port, &settings.doh_token, &server_ip),
            config: ConfigView {
                hostname: settings.hostname.clone(),
                dns_listen: settings.dns_listen.clone(),
                doh_listen: settings.doh_listen.clone(),
                admin_listen: settings.admin_listen.clone(),
                clients: settings.clients.clone(),
                upstreams: settings.upstreams.clone(),
                block_mode: settings.block_mode.clone(),
                paused: settings.paused,
                allow: settings.allow.clone(),
                deny: settings.deny.clone(),
                rewrites: settings.rewrites.clone(),
                blocklists,
                self_signed: settings.self_signed,
                token: settings.doh_token.clone(),
            },
            stats: week,
            days,
            log,
        };
        serde_json::to_value(view).unwrap_or(serde_json::Value::Null)
    }

    pub async fn handle_packet(&self, packet: &[u8], from: IpAddr, transport: Transport) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }
        let peer = normalize(from);
        if transport != Transport::Doh && !self.admitted(peer) {
            return None;
        }
        let started = Instant::now();
        let request = match Message::from_vec(packet) {
            Ok(message) => message,
            Err(_) => {
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                return Some(emit(&error_message(id, OpCode::Query, ResponseCode::FormErr, None), 512));
            }
        };
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        let from = client_of(&request, transport, peer);
        if !self.allow_rate(from) {
            self.record(from, "-", "-", "limited", started);
            return Some(emit(&error_message(request.metadata.id, request.metadata.op_code, ResponseCode::ServFail, None), 512));
        }
        if request.metadata.op_code != OpCode::Query || request.queries.len() != 1 {
            return Some(emit(
                &error_message(request.metadata.id, request.metadata.op_code, ResponseCode::FormErr, None),
                512,
            ));
        }
        let query = request.queries[0].clone();
        if query.query_class != hickory_proto::rr::DNSClass::IN {
            return Some(emit(
                &error_message(request.metadata.id, OpCode::Query, ResponseCode::NotImp, Some(query)),
                512,
            ));
        }
        let limit = match transport {
            Transport::Udp => udp_limit(&request),
            Transport::Tcp | Transport::Doh => 65535,
        };
        let name = query.name.to_string();
        let qtype = query.query_type.to_string();
        let domain = Domain::parse(&name);
        let settings = self.settings.load();
        let decision = domain
            .as_ref()
            .map(|item| classify(&self.filter.load(), settings.paused, item))
            .unwrap_or(Local::Forward);
        let (action, message) = match decision {
            Local::Rewrite(address) => ("rewritten", address_message(&request, &query, address)),
            Local::Special => ("local", error_message(request.metadata.id, OpCode::Query, ResponseCode::NXDomain, Some(query.clone()))),
            Local::Blocked => ("blocked", blocked_message(&request, &query, &settings.block_mode)),
            Local::Allowed | Local::Forward => self.forwarded(&request, &query).await,
        };
        drop(settings);
        self.finish(action);
        self.record(from, &name.trim_end_matches('.').to_ascii_lowercase(), &qtype, action, started);
        Some(emit(&message, limit))
    }

    async fn forwarded(&self, request: &Message, query: &hickory_proto::op::Query) -> (&'static str, Message) {
        let key = format!("{} {}", query.name.to_ascii().to_ascii_lowercase(), query.query_type);
        if let Some(message) = self.fresh(&key, request.metadata.id) {
            return ("cached", message);
        }
        let outcome = self.flight_resolve(key.clone(), request, query).await;
        match outcome {
            Ok(message) => {
                self.store(&key, &message);
                let mut message = message;
                message.metadata.id = request.metadata.id;
                message.metadata.recursion_available = true;
                message.metadata.recursion_desired = request.metadata.recursion_desired;
                if message.queries.is_empty() {
                    message.add_query(query.clone());
                }
                ("forwarded", message)
            }
            Err(()) => {
                if let Some(message) = self.stale(&key, request.metadata.id) {
                    ("stale", message)
                } else {
                    (
                        "failed",
                        error_message(request.metadata.id, OpCode::Query, ResponseCode::ServFail, Some(query.clone())),
                    )
                }
            }
        }
    }

    async fn flight_resolve(&self, key: String, request: &Message, query: &hickory_proto::op::Query) -> Result<Message, ()> {
        let waiting = {
            let mut map = self.flight.inflight.lock().unwrap();
            if let Some(sender) = map.get(&key).cloned() {
                Some(sender)
            } else {
                let (sender, _receiver) = watch::channel(None);
                map.insert(key.clone(), sender.clone());
                None
            }
        };
        if let Some(sender) = waiting {
            let mut receiver = sender.subscribe();
            loop {
                if let Some(result) = receiver.borrow().clone() {
                    return result;
                }
                if receiver.changed().await.is_err() {
                    return Err(());
                }
            }
        }
        let sender = self.flight.inflight.lock().unwrap().get(&key).cloned().ok_or(())?;
        let mut leader = Leader {
            flight: &self.flight,
            key,
            sender,
            published: false,
        };
        let upstream = upstream_query(request, query);
        let pool = self.pool.load_full();
        let result = pool.resolve(&upstream).await;
        let _ = leader.sender.send(Some(result.clone()));
        leader.published = true;
        result
    }

    fn fresh(&self, key: &str, id: u16) -> Option<Message> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.get(key)?;
        let now = Instant::now();
        if now >= entry.expires {
            return None;
        }
        let remain = entry.expires.saturating_duration_since(now).as_secs().clamp(1, 3600) as u32;
        Some(adjust(entry.message.clone(), id, remain))
    }

    fn stale(&self, key: &str, id: u16) -> Option<Message> {
        let cache = self.cache.lock().unwrap();
        let entry = cache.get(key)?;
        let now = Instant::now();
        if now < entry.expires || now >= entry.stale_until {
            return None;
        }
        Some(adjust(entry.message.clone(), id, 30))
    }

    fn store(&self, key: &str, message: &Message) {
        if message.metadata.truncation || matches!(message.metadata.response_code, ResponseCode::ServFail | ResponseCode::Refused) {
            return;
        }
        let Some(ttl) = record_ttl(message) else { return };
        if ttl == 0 {
            return;
        }
        let ttl = ttl.clamp(1, 3600);
        let expires = Instant::now() + Duration::from_secs(u64::from(ttl));
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= 100_000 {
            let now = Instant::now();
            cache.retain(|_, entry| entry.stale_until > now);
        }
        cache.insert(key.to_string(), CacheEntry {
            expires,
            stale_until: expires + Duration::from_secs(3600),
            message: message.clone(),
        });
    }

    fn admitted(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let text = ip.to_string();
        self.settings.load().clients.iter().any(|item| item == &text)
    }

    fn allow_rate(&self, ip: IpAddr) -> bool {
        let mut rates = self.rates.lock().unwrap();
        let now = Instant::now();
        let entry = rates.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= Duration::from_secs(1) {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= 500
    }

    fn finish(&self, action: &str) {
        match action {
            "blocked" => self.counters.blocked.fetch_add(1, Ordering::Relaxed),
            "cached" | "stale" => self.counters.cached.fetch_add(1, Ordering::Relaxed),
            "rewritten" => self.counters.rewritten.fetch_add(1, Ordering::Relaxed),
            "failed" | "limited" => self.counters.failed.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    fn record(&self, client: IpAddr, name: &str, qtype: &str, action: &'static str, started: Instant) {
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        let mut journal = self.journal.lock().unwrap();
        note_day(&mut journal, name, action);
        if journal.lines.len() == 2000 {
            journal.lines.pop_front();
        }
        journal.lines.push_back(LogLine {
            time: chrono::Local::now().format("%d.%m. %H:%M:%S").to_string(),
            client: client.to_string(),
            name: name.to_string(),
            qtype: qtype.to_string(),
            action,
            ms: started.elapsed().as_millis(),
        });
    }

    fn load_history(&self) {
        let directory = self.directory.join("history");
        let mut days = Vec::new();
        let oldest = oldest_day();
        let Ok(entries) = std::fs::read_dir(&directory) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Ok(day) = serde_json::from_str::<DayRoll>(&text) else { continue };
            if day.date < oldest {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            days.push(day);
        }
        days.sort_by(|left, right| left.date.cmp(&right.date));
        self.journal.lock().unwrap().days = days;
    }

    fn flush_history(&self) {
        let snapshot = {
            let mut journal = self.journal.lock().unwrap();
            let oldest = oldest_day();
            journal.days.retain(|day| day.date >= oldest);
            if !journal.dirty {
                return;
            }
            journal.dirty = false;
            journal.days.clone()
        };
        let directory = self.directory.join("history");
        if std::fs::create_dir_all(&directory).is_err() {
            self.journal.lock().unwrap().dirty = true;
            return;
        }
        for day in &snapshot {
            let path = directory.join(format!("{}.json", day.date));
            let temp = directory.join(format!("{}.json.tmp", day.date));
            let Ok(text) = serde_json::to_string(day) else { continue };
            if std::fs::write(&temp, text).is_ok() {
                let _ = std::fs::rename(&temp, &path);
            }
        }
        if let Ok(entries) = std::fs::read_dir(&directory) {
            let oldest = oldest_day();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(date) = name.strip_suffix(".json") else { continue };
                if date < oldest.as_str() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

struct Leader<'a> {
    flight: &'a Flight,
    key: String,
    sender: watch::Sender<Option<Result<Message, ()>>>,
    published: bool,
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = self.sender.send(Some(Err(())));
        }
        if let Ok(mut map) = self.flight.inflight.lock() {
            map.remove(&self.key);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Doh,
}

fn note_error(lists: &mut Lists, item: &BlocklistConfig, error: String) {
    let previous = lists.domains.get(&item.id).map(Vec::len).unwrap_or(0);
    let updated = lists.meta.get(&item.id).and_then(|meta| meta.updated.clone());
    lists.meta.insert(item.id.clone(), ListMeta { domains: previous, updated, error: Some(error) });
}

fn apply_patch(settings: &mut Settings, patch: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    if let Some(value) = patch.get("hostname").and_then(|item| item.as_str()) {
        settings.hostname = value.to_string();
    }
    if let Some(value) = patch.get("dnsListen").and_then(|item| item.as_str()) {
        parse_addr(value)?;
        settings.dns_listen = value.to_string();
    }
    if let Some(value) = patch.get("dohListen").and_then(|item| item.as_str()) {
        parse_addr(value)?;
        settings.doh_listen = value.to_string();
    }
    if let Some(value) = patch.get("blockMode").and_then(|item| item.as_str()) {
        settings.block_mode = value.to_string();
    }
    if let Some(value) = patch.get("paused").and_then(|item| item.as_bool()) {
        settings.paused = value;
    }
    if let Some(value) = patch.get("selfSigned").and_then(|item| item.as_bool()) {
        settings.self_signed = value;
    }
    if let Some(value) = patch.get("clients") {
        settings.clients = ip_list(value)?;
    }
    if let Some(value) = patch.get("upstreams") {
        let upstreams = upstream_list(value)?;
        if upstreams.is_empty() {
            return Err("Mindestens eine Weiterleitung eintragen.".into());
        }
        settings.upstreams = upstreams;
    }
    if let Some(value) = patch.get("allow") {
        settings.allow = string_list(value);
    }
    if let Some(value) = patch.get("deny") {
        settings.deny = string_list(value);
    }
    if let Some(value) = patch.get("rewrites") {
        settings.rewrites = value
            .as_array()
            .ok_or("Umleitungen sind ungültig.")?
            .iter()
            .filter_map(|item| {
                Some(config::RewriteConfig {
                    name: item.get("name")?.as_str()?.to_string(),
                    address: item.get("address")?.as_str()?.to_string(),
                })
            })
            .collect();
    }
    if let Some(value) = patch.get("blocklists") {
        settings.blocklists = value
            .as_array()
            .ok_or("Sperrlisten sind ungültig.")?
            .iter()
            .filter_map(|item| {
                Some(BlocklistConfig {
                    id: item.get("id")?.as_str()?.to_string(),
                    name: item.get("name")?.as_str()?.to_string(),
                    url: item.get("url")?.as_str()?.to_string(),
                    enabled: item.get("enabled").and_then(|flag| flag.as_bool()).unwrap_or(true),
                })
            })
            .collect();
    }
    Ok(())
}

fn upstream_list(value: &serde_json::Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in value.as_array().ok_or("Liste ist ungültig.")? {
        let text = item.as_str().ok_or("Eintrag ist ungültig.")?.trim();
        if text.is_empty() {
            continue;
        }
        let shown = config::canonical_upstream(text)?;
        if !out.contains(&shown) {
            out.push(shown);
        }
    }
    Ok(out)
}

fn ip_list(value: &serde_json::Value) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in value.as_array().ok_or("Liste ist ungültig.")? {
        let text = item.as_str().ok_or("Eintrag ist ungültig.")?.trim();
        if text.is_empty() {
            continue;
        }
        let ip: IpAddr = text.parse().map_err(|_| format!("{text} ist keine IP."))?;
        let shown = ip.to_string();
        if !out.contains(&shown) {
            out.push(shown);
        }
    }
    Ok(out)
}

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn upstream_query(request: &Message, query: &hickory_proto::op::Query) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.metadata.checking_disabled = request.metadata.checking_disabled;
    message.add_query(query.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    let dnssec_ok = request.edns.as_ref().is_some_and(|item| item.flags().dnssec_ok);
    edns.set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    message
}

fn blocked_message(request: &Message, query: &hickory_proto::op::Query, mode: &str) -> Message {
    if mode == "zero" && query.query_type == RecordType::A {
        return address_message(request, query, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    if mode == "zero" && query.query_type == RecordType::AAAA {
        return address_message(request, query, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }
    error_message(request.metadata.id, OpCode::Query, ResponseCode::NXDomain, Some(query.clone()))
}

fn address_message(request: &Message, query: &hickory_proto::op::Query, address: IpAddr) -> Message {
    let mut message = error_message(request.metadata.id, OpCode::Query, ResponseCode::NoError, Some(query.clone()));
    let record = match (query.query_type, address) {
        (RecordType::A, IpAddr::V4(ip)) => Some(Record::from_rdata(query.name.clone(), 60, RData::A(A(ip)))),
        (RecordType::AAAA, IpAddr::V6(ip)) => Some(Record::from_rdata(query.name.clone(), 60, RData::AAAA(AAAA(ip)))),
        _ => None,
    };
    if let Some(record) = record {
        message.add_answer(record);
    }
    message
}

fn error_message(id: u16, opcode: OpCode, code: ResponseCode, query: Option<hickory_proto::op::Query>) -> Message {
    let mut message = Message::response(id, opcode);
    message.metadata.response_code = code;
    message.metadata.recursion_available = true;
    message.metadata.recursion_desired = true;
    if let Some(query) = query {
        message.add_query(query);
    }
    message
}

fn adjust(mut message: Message, id: u16, ttl: u32) -> Message {
    message.metadata.id = id;
    message.metadata.recursion_available = true;
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = ttl;
    }
    message
}

fn record_ttl(message: &Message) -> Option<u32> {
    let mut values = message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .map(|record| record.ttl);
    let first = values.next()?;
    Some(values.fold(first, u32::min))
}

fn udp_limit(request: &Message) -> usize {
    match &request.edns {
        Some(edns) => usize::from(edns.max_payload()).clamp(512, 4096),
        None => 512,
    }
}

fn emit(message: &Message, limit: usize) -> Vec<u8> {
    match message.to_vec() {
        Ok(bytes) if bytes.len() <= limit => bytes,
        Ok(_) => message.truncate().to_vec().unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn oldest_day() -> String {
    let today = chrono::Local::now().date_naive();
    let start = today - chrono::Days::new(6);
    start.format("%Y-%m-%d").to_string()
}

fn note_day(journal: &mut Journal, name: &str, action: &str) {
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    if journal.days.last().map(|day| day.date.as_str()) != Some(date.as_str()) {
        journal.days.push(DayRoll {
            date,
            total: 0,
            blocked: 0,
            cached: 0,
            rewritten: 0,
            failed: 0,
            names: HashMap::new(),
            blocked_names: HashMap::new(),
        });
    }
    let day = journal.days.last_mut().unwrap();
    day.total += 1;
    match action {
        "blocked" => {
            day.blocked += 1;
            *day.blocked_names.entry(name.to_string()).or_insert(0) += 1;
        }
        "cached" | "stale" => {
            day.cached += 1;
            *day.names.entry(name.to_string()).or_insert(0) += 1;
        }
        "rewritten" => {
            day.rewritten += 1;
            *day.names.entry(name.to_string()).or_insert(0) += 1;
        }
        "failed" | "limited" => {
            day.failed += 1;
            *day.names.entry(name.to_string()).or_insert(0) += 1;
        }
        _ => {
            *day.names.entry(name.to_string()).or_insert(0) += 1;
        }
    }
    trim_counts(&mut day.names);
    trim_counts(&mut day.blocked_names);
    journal.dirty = true;
}

fn week_view(stored: &[DayRoll]) -> (StatsView, Vec<DayView>) {
    let mut names = HashMap::new();
    let mut blocked_names = HashMap::new();
    let mut by_date = HashMap::new();
    for day in stored {
        by_date.insert(day.date.clone(), day);
        add_counts(&mut names, &day.names);
        add_counts(&mut blocked_names, &day.blocked_names);
    }
    let today = chrono::Local::now().date_naive();
    let mut days = Vec::new();
    let mut total = 0;
    let mut blocked = 0;
    let mut cached = 0;
    let mut rewritten = 0;
    let mut failed = 0;
    for offset in 0..7 {
        let date = (today - chrono::Days::new(offset)).format("%Y-%m-%d").to_string();
        let row = by_date.get(&date);
        let view = DayView {
            date,
            total: row.map(|day| day.total).unwrap_or(0),
            blocked: row.map(|day| day.blocked).unwrap_or(0),
            cached: row.map(|day| day.cached).unwrap_or(0),
            rewritten: row.map(|day| day.rewritten).unwrap_or(0),
            failed: row.map(|day| day.failed).unwrap_or(0),
        };
        total += view.total;
        blocked += view.blocked;
        cached += view.cached;
        rewritten += view.rewritten;
        failed += view.failed;
        days.push(view);
    }
    (
        StatsView {
            total,
            blocked,
            cached,
            rewritten,
            failed,
            top: top_names(&names, 10),
            blocked_top: top_names(&blocked_names, 8),
            blocked_all: ranked_names(&blocked_names),
        },
        days,
    )
}

fn add_counts(target: &mut HashMap<String, u64>, source: &HashMap<String, u64>) {
    for (name, count) in source {
        *target.entry(name.clone()).or_insert(0) += count;
    }
}

fn ranked_names(counts: &HashMap<String, u64>) -> Vec<NameCount> {
    let mut rows: Vec<_> = counts
        .iter()
        .map(|(name, count)| NameCount { name: name.clone(), count: *count })
        .collect();
    rows.sort_by(|left, right| right.count.cmp(&left.count).then_with(|| left.name.cmp(&right.name)));
    rows
}

fn top_names(counts: &HashMap<String, u64>, limit: usize) -> Vec<NameCount> {
    let mut rows = ranked_names(counts);
    rows.truncate(limit);
    rows
}

fn trim_counts(counts: &mut HashMap<String, u64>) {
    if counts.len() <= 4000 {
        return;
    }
    let mut rows: Vec<_> = counts.iter().map(|(name, count)| (name.clone(), *count)).collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1));
    rows.truncate(1000);
    *counts = rows.into_iter().collect();
}

fn client_of(request: &Message, transport: Transport, peer: IpAddr) -> IpAddr {
    if transport != Transport::Doh {
        return peer;
    }
    let Some(edns) = &request.edns else { return peer };
    let Some(EdnsOption::Subnet(subnet)) = edns.option(EdnsCode::Subnet) else { return peer };
    let address = subnet.addr();
    let complete = match address {
        IpAddr::V4(_) => subnet.source_prefix() == 32,
        IpAddr::V6(_) => subnet.source_prefix() == 128,
    };
    if complete { address } else { peer }
}

fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(value)),
        other => other,
    }
}

fn server_ip() -> String {
    let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return "127.0.0.1".into();
    };
    if socket.connect("1.1.1.1:80").is_err() {
        return "127.0.0.1".into();
    }
    socket
        .local_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

fn parse_addr(value: &str) -> Result<SocketAddr, String> {
    value.parse().map_err(|_| format!("Adresse {value} ist ungültig."))
}

fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let family = if addr.is_ipv4() { SocketFamily::IPV4 } else { SocketFamily::IPV6 };
    let socket = Socket::new(family, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let family = if addr.is_ipv4() { SocketFamily::IPV4 } else { SocketFamily::IPV6 };
    let socket = Socket::new(family, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn spawn_udp(socket: UdpSocket, app: Arc<App>) {
    let socket = Arc::new(socket);
    let listener = socket.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((size, peer)) = listener.recv_from(&mut buffer).await else { break };
            let packet = buffer[..size].to_vec();
            let app = app.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Some(reply) = app.handle_packet(&packet, peer.ip(), Transport::Udp).await {
                    let _ = socket.send_to(&reply, peer).await;
                }
            });
        }
    });
}

fn spawn_tcp(listener: TcpListener, app: Arc<App>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { break };
            let app = app.clone();
            tokio::spawn(async move {
                let _ = read_tcp(stream, peer.ip(), app).await;
            });
        }
    });
}

async fn read_tcp(mut stream: TcpStream, peer: IpAddr, app: Arc<App>) {
    if !app.admitted(normalize(peer)) {
        return;
    }
    let _ = stream.set_nodelay(true);
    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let mut head = [0u8; 2];
            if stream.read_exact(&mut head).await.is_err() {
                break;
            }
            let size = u16::from_be_bytes(head) as usize;
            if size == 0 || size > 65535 {
                break;
            }
            let mut packet = vec![0u8; size];
            if stream.read_exact(&mut packet).await.is_err() {
                break;
            }
            if let Some(reply) = app.handle_packet(&packet, peer, Transport::Tcp).await {
                let Ok(length) = u16::try_from(reply.len()) else { break };
                if stream.write_all(&length.to_be_bytes()).await.is_err() || stream.write_all(&reply).await.is_err() {
                    break;
                }
            }
        }
    })
    .await;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StateView {
    running: bool,
    error: String,
    blocked_domains: usize,
    server_ip: String,
    doh_url: String,
    restart_required: bool,
    routeros: String,
    config: ConfigView,
    stats: StatsView,
    days: Vec<DayView>,
    log: Vec<LogView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DayView {
    date: String,
    total: u64,
    blocked: u64,
    cached: u64,
    rewritten: u64,
    failed: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigView {
    hostname: String,
    dns_listen: String,
    doh_listen: String,
    admin_listen: String,
    clients: Vec<String>,
    upstreams: Vec<String>,
    block_mode: String,
    paused: bool,
    allow: Vec<String>,
    deny: Vec<String>,
    rewrites: Vec<config::RewriteConfig>,
    blocklists: Vec<ListView>,
    self_signed: bool,
    token: String,
}

#[derive(Serialize)]
struct ListView {
    id: String,
    name: String,
    url: String,
    enabled: bool,
    domains: usize,
    updated: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsView {
    total: u64,
    blocked: u64,
    cached: u64,
    rewritten: u64,
    failed: u64,
    top: Vec<NameCount>,
    blocked_top: Vec<NameCount>,
    blocked_all: Vec<NameCount>,
}

#[derive(Serialize)]
struct NameCount {
    name: String,
    count: u64,
}

#[derive(Serialize)]
struct LogView {
    time: String,
    client: String,
    name: String,
    #[serde(rename = "type")]
    r#type: String,
    action: &'static str,
    ms: u128,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::rdata::opt::ClientSubnet;

    use super::*;

    fn stamped(prefix: u8) -> Message {
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        let mut edns = Edns::new();
        edns.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 88, 23)),
            prefix,
            0,
        )));
        message.set_edns(edns);
        message
    }

    #[test]
    fn doh_keeps_a_full_client_address() {
        let peer = IpAddr::V4(Ipv4Addr::new(79, 252, 113, 40));
        assert_eq!(
            client_of(&stamped(32), Transport::Doh, peer),
            IpAddr::V4(Ipv4Addr::new(192, 168, 88, 23))
        );
        assert_eq!(client_of(&stamped(32), Transport::Udp, peer), peer);
        assert_eq!(client_of(&stamped(24), Transport::Doh, peer), peer);
    }
}
