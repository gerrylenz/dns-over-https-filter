use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::filter::{Domain, Filter, Rewrite};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub hostname: String,
    pub dns_listen: String,
    pub doh_listen: String,
    pub admin_listen: String,
    pub clients: Vec<String>,
    pub upstreams: Vec<String>,
    pub block_mode: String,
    pub paused: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub rewrites: Vec<RewriteConfig>,
    pub blocklists: Vec<BlocklistConfig>,
    pub doh_token: String,
    pub self_signed: bool,
    pub cert_hostname: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewriteConfig {
    pub name: String,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocklistConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            dns_listen: "0.0.0.0:5353".into(),
            doh_listen: "0.0.0.0:8443".into(),
            admin_listen: "127.0.0.1:8080".into(),
            clients: Vec::new(),
            upstreams: vec!["1.1.1.1".into(), "9.9.9.9".into()],
            block_mode: "nxdomain".into(),
            paused: false,
            allow: Vec::new(),
            deny: Vec::new(),
            rewrites: Vec::new(),
            blocklists: presets(),
            doh_token: new_token(),
            self_signed: true,
            cert_hostname: "localhost".into(),
        }
    }
}

pub fn presets() -> Vec<BlocklistConfig> {
    vec![
        BlocklistConfig {
            id: "oisd-small".into(),
            name: "OISD Small".into(),
            url: "https://small.oisd.nl/domainswild".into(),
            enabled: false,
        },
        BlocklistConfig {
            id: "hagezi-pro".into(),
            name: "HaGeZi Pro".into(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt".into(),
            enabled: true,
        },
        BlocklistConfig {
            id: "hagezi-tif".into(),
            name: "HaGeZi TIF".into(),
            url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt".into(),
            enabled: true,
        },
        BlocklistConfig {
            id: "nrd-7".into(),
            name: "Neu registrierte Domains, 7 Tage".into(),
            url: "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt".into(),
            enabled: false,
        },
    ]
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("Zufall fehlt");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let settings = Settings::default();
            settings.save(path)?;
            return Ok(settings);
        }
        let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let mut settings: Settings = toml::from_str(&text).map_err(|error| error.to_string())?;
        if settings.doh_token.len() < 32 {
            settings.doh_token = new_token();
            settings.save(path)?;
        }
        settings.normalize();
        Ok(settings)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let body = toml::to_string_pretty(self).map_err(|error| error.to_string())?;
        let text = format!(
            "# Unbound hört nur lokal. doh_listen ist die Adresse für den RB5009.\n{body}"
        );
        let temp = path.with_extension("toml.tmp");
        fs::write(&temp, text).map_err(|error| error.to_string())?;
        fs::rename(temp, path).map_err(|error| error.to_string())
    }

    pub fn normalize(&mut self) {
        self.allow = names(&self.allow);
        self.deny = names(&self.deny);
        self.rewrites = rewrites(&self.rewrites);
        self.upstreams = normalize_upstreams(&self.upstreams);
        if self.upstreams.is_empty() {
            self.upstreams = vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()];
        }
        self.clients = ips(&self.clients, 64);
        if self.block_mode != "zero" {
            self.block_mode = "nxdomain".into();
        }
        self.blocklists = sanitize_lists(&self.blocklists);
        self.hostname = sanitize_hostname(&self.hostname);
    }

}

pub fn names(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let Some(domain) = Domain::parse(value) else { continue };
        if domain.as_str().contains('.') && !out.iter().any(|item: &String| item == &domain.as_str()) {
            out.push(domain.as_str());
        }
        if out.len() == 500 {
            break;
        }
    }
    out
}

fn rewrites(values: &[RewriteConfig]) -> Vec<RewriteConfig> {
    let mut out = Vec::new();
    for value in values {
        let raw = value.name.trim().trim_end_matches('.').to_ascii_lowercase();
        let wildcard = raw.starts_with("*.");
        let bare = raw.trim_start_matches("*.");
        if Domain::parse(bare).is_none() || value.address.parse::<IpAddr>().is_err() {
            continue;
        }
        let name = if wildcard {
            format!("*.{bare}")
        } else {
            bare.to_string()
        };
        if out.iter().any(|item: &RewriteConfig| item.name == name) {
            continue;
        }
        out.push(RewriteConfig {
            name,
            address: value.address.trim().to_string(),
        });
        if out.len() == 500 {
            break;
        }
    }
    out
}

fn normalize_upstreams(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let Ok(item) = canonical_upstream(value.trim()) else { continue };
        if !out.contains(&item) {
            out.push(item);
        }
        if out.len() == 4 {
            break;
        }
    }
    out
}

pub fn canonical_upstream(text: &str) -> Result<String, String> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr.to_string());
    }
    let ip: IpAddr = text.parse().map_err(|_| format!("{text} ist keine Adresse."))?;
    Ok(SocketAddr::new(ip, 53).to_string())
}

fn ips(values: &[String], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        if let Ok(ip) = value.trim().parse::<IpAddr>() {
            let text = ip.to_string();
            if !out.contains(&text) {
                out.push(text);
            }
        }
        if out.len() == limit {
            break;
        }
    }
    out
}

fn sanitize_hostname(value: &str) -> String {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.contains(['/', ' ', '\\'])
        || host.parse::<SocketAddr>().is_ok()
    {
        return "localhost".into();
    }
    host
}

fn sanitize_lists(values: &[BlocklistConfig]) -> Vec<BlocklistConfig> {
    let mut by_id = Vec::new();
    for item in values {
        if !valid_id(&item.id) || !item.url.starts_with("https://") || item.url.len() > 400 {
            continue;
        }
        let name = {
            let trimmed = item.name.trim();
            if trimmed.is_empty() { item.id.clone() } else { trimmed.chars().take(80).collect() }
        };
        if by_id.iter().any(|existing: &BlocklistConfig| existing.id == item.id) {
            continue;
        }
        by_id.push(BlocklistConfig {
            id: item.id.clone(),
            name,
            url: item.url.trim().to_string(),
            enabled: item.enabled,
        });
    }
    by_id.truncate(20);
    by_id
}

pub fn build_filter(settings: &Settings, lists: &[(String, bool, Vec<String>)]) -> Filter {
    let mut filter = Filter::default();
    for (id, enabled, domains) in lists {
        if !enabled {
            continue;
        }
        let Some(configured) = settings.blocklists.iter().find(|item| &item.id == id) else {
            continue;
        };
        if !configured.enabled {
            continue;
        }
        for domain in domains {
            if let Some(parsed) = Domain::parse(domain) {
                filter.block.insert(&parsed);
            }
        }
    }
    for name in &settings.deny {
        if let Some(parsed) = Domain::parse(name) {
            filter.deny.insert(&parsed);
        }
    }
    for name in &settings.allow {
        if let Some(parsed) = Domain::parse(name) {
            filter.allow.insert(&parsed);
        }
    }
    for rule in &settings.rewrites {
        let wildcard = rule.name.starts_with("*.");
        let name = rule.name.trim_start_matches("*.").to_string();
        if let Ok(address) = rule.address.parse() {
            filter.insert_rewrite(Rewrite {
                name,
                address,
                wildcard,
            });
        }
    }
    filter
}

pub fn config_path_from_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data/server.toml")
}

pub fn doh_url(hostname: &str, port: u16, token: &str) -> String {
    if port == 443 {
        format!("https://{hostname}/{token}")
    } else {
        format!("https://{hostname}:{port}/{token}")
    }
}

pub fn routeros(hostname: &str, port: u16, token: &str, server_ip: &str) -> String {
    let url = doh_url(hostname, port, token);
    format!(
        "/ip dns static add name={hostname} address={server_ip}\n\
         /ip dns set allow-remote-requests=yes use-doh-server=\"{url}\" verify-doh-cert=yes servers=\"\"\n\
         /certificate settings set crl-use=no"
    )
}
