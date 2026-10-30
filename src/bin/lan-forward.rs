//! Nimmt DNS aus dem LAN an und schickt die Geräteadresse per DoH mit.
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listen = arg("--listen").unwrap_or_else(|| "0.0.0.0:53".into());
    let doh = arg("--doh").or_else(|| env::var("DOH_URL").ok()).expect("DOH_URL oder --doh fehlt");
    let address: SocketAddr = listen.parse().expect("Adresse ist ungültig");
    let client = Arc::new(Doh::new(&doh).expect("DoH-Adresse ist ungültig"));
    let block_file = arg("--block")
        .or_else(|| env::var("BLOCK_FILE").ok())
        .unwrap_or_else(|| "/sperre/liste.txt".into());
    let blocks = Arc::new(RwLock::new(Vec::new()));
    {
        let mut seen = None;
        reload(&block_file, &blocks, &mut seen);
    }
    let watch_file = block_file.clone();
    let watch_blocks = Arc::clone(&blocks);
    tokio::spawn(async move { watch_blocks_file(watch_file, watch_blocks).await });
    eprintln!("LAN-Weiterleiter hört auf {address}");
    let udp = Arc::clone(&client);
    let udp_blocks = Arc::clone(&blocks);
    let tcp = client;
    tokio::spawn(async move { serve_udp(address, udp, udp_blocks).await });
    serve_tcp(address, tcp, blocks).await;
}

fn arg(name: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(item) = args.next() {
        if item == name {
            return args.next();
        }
        if let Some(value) = item.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

struct Doh {
    uri: Uri,
    host: String,
    port: u16,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    sender: Mutex<Option<http2::SendRequest<Full<Bytes>>>>,
}

impl Doh {
    fn new(url: &str) -> Result<Self, String> {
        let uri: Uri = url.parse().map_err(|error| format!("{error}"))?;
        if uri.scheme_str() != Some("https") {
            return Err("DoH braucht https".into());
        }
        let host = uri.host().ok_or("Host fehlt")?.to_string();
        let port = uri.port_u16().unwrap_or(443);
        let name = ServerName::try_from(host.clone()).map_err(|error| error.to_string())?.to_owned();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            uri,
            host,
            port,
            name,
            tls: Arc::new(tls),
            sender: Mutex::new(None),
        })
    }

    async fn ask(&self, message: &Message) -> Result<Message, ()> {
        let bytes = message.to_vec().map_err(|_| ())?;
        let request = Request::post(self.uri.clone())
            .header("host", if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) })
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|_| ())?;
        let response = timeout(Duration::from_secs(5), self.send(request)).await.map_err(|_| ())??;
        if response.status() != http::StatusCode::OK {
            return Err(());
        }
        let body = response.into_body().collect().await.map_err(|_| ())?.to_bytes();
        Message::from_vec(&body).map_err(|_| ())
    }

    async fn send(&self, request: Request<Full<Bytes>>) -> Result<http::Response<Incoming>, ()> {
        let mut sender = self.ready().await?;
        match sender.send_request(request).await {
            Ok(response) => Ok(response),
            Err(_) => {
                *self.sender.lock().await = None;
                Err(())
            }
        }
    }

    async fn ready(&self) -> Result<http2::SendRequest<Full<Bytes>>, ()> {
        let mut guard = self.sender.lock().await;
        if let Some(sender) = guard.as_ref() {
            if sender.is_ready() && !sender.is_closed() {
                return Ok(sender.clone());
            }
        }
        let stream = TcpStream::connect((self.host.as_str(), self.port)).await.map_err(|_| ())?;
        let tls = TlsConnector::from(Arc::clone(&self.tls));
        let tls = tls.connect(self.name.clone(), stream).await.map_err(|_| ())?;
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        *guard = Some(sender.clone());
        Ok(sender)
    }
}

fn stamp(message: &mut Message, client: std::net::IpAddr) {
    let prefix = if client.is_ipv4() { 32 } else { 128 };
    let mut edns = message.edns.clone().unwrap_or_else(Edns::new);
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(client, prefix, 0)));
    if edns.max_payload() < 1232 {
        edns.set_max_payload(1232);
    }
    message.set_edns(edns);
}

fn parse_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim().trim_end_matches('.').to_ascii_lowercase();
        let line = line.strip_prefix("*.").unwrap_or(line.as_str());
        if line.is_empty() || !line.contains('.') || line.contains(char::is_whitespace) {
            continue;
        }
        let ok = line.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
        if !ok || out.iter().any(|item| item == line) {
            continue;
        }
        out.push(line.to_string());
        if out.len() == 500 {
            break;
        }
    }
    out
}

fn hits(rules: &[String], raw: &str) -> bool {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    rules.iter().any(|rule| name == *rule || name.ends_with(&format!(".{rule}")))
}

fn locally_blocked(blocks: &RwLock<Vec<String>>, request: &Message) -> bool {
    let Some(query) = request.queries.first() else { return false };
    let rules = blocks.read().unwrap_or_else(|error| error.into_inner());
    hits(&rules, &query.name.to_utf8())
}

fn refuse(request: &Message) -> Vec<u8> {
    let mut message = Message::response(request.metadata.id, request.metadata.op_code);
    message.metadata.response_code = ResponseCode::NXDomain;
    message.metadata.recursion_available = true;
    message.metadata.recursion_desired = request.metadata.recursion_desired;
    if let Some(query) = request.queries.first() {
        message.add_query(query.clone());
    }
    message.to_vec().unwrap_or_default()
}

fn reload(path: &str, blocks: &RwLock<Vec<String>>, seen: &mut Option<String>) {
    let text = std::fs::read_to_string(path).unwrap_or_default().replace("\r\n", "\n");
    if seen.as_deref() == Some(text.as_str()) {
        return;
    }
    let names = parse_blocks(&text);
    let count = names.len();
    *blocks.write().unwrap_or_else(|error| error.into_inner()) = names;
    eprintln!("Sperrliste: {count} Namen aus {path}");
    *seen = Some(text);
}

async fn watch_blocks_file(path: String, blocks: Arc<RwLock<Vec<String>>>) {
    let mut seen = Some(std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n"));
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        reload(&path, &blocks, &mut seen);
    }
}

async fn serve_udp(address: SocketAddr, client: Arc<Doh>, blocks: Arc<RwLock<Vec<String>>>) {
    let socket = Arc::new(UdpSocket::bind(address).await.expect("UDP ist nicht frei"));
    let mut buffer = [0u8; 4096];
    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else { continue };
        let socket = Arc::clone(&socket);
        let client = Arc::clone(&client);
        let blocks = Arc::clone(&blocks);
        let packet = buffer[..size].to_vec();
        tokio::spawn(async move {
            let Ok(mut request) = Message::from_vec(&packet) else { return };
            if request.metadata.message_type != MessageType::Query {
                return;
            }
            if locally_blocked(&blocks, &request) {
                let _ = socket.send_to(&refuse(&request), peer).await;
                return;
            }
            let limit = request.edns.as_ref().map(|item| usize::from(item.max_payload())).unwrap_or(512);
            stamp(&mut request, peer.ip());
            let Ok(mut response) = client.ask(&request).await else { return };
            response.metadata.id = request.metadata.id;
            let bytes = match response.to_vec() {
                Ok(bytes) if bytes.len() <= limit => bytes,
                Ok(_) => response.truncate().to_vec().unwrap_or_default(),
                Err(_) => return,
            };
            let _ = socket.send_to(&bytes, peer).await;
        });
    }
}

async fn serve_tcp(address: SocketAddr, client: Arc<Doh>, blocks: Arc<RwLock<Vec<String>>>) {
    let listener = TcpListener::bind(address).await.expect("TCP ist nicht frei");
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else { continue };
        let client = Arc::clone(&client);
        let blocks = Arc::clone(&blocks);
        tokio::spawn(async move {
            loop {
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let length = u16::from_be_bytes(head) as usize;
                let mut packet = vec![0u8; length];
                if stream.read_exact(&mut packet).await.is_err() {
                    return;
                }
                let Ok(mut request) = Message::from_vec(&packet) else { return };
                if locally_blocked(&blocks, &request) {
                    let bytes = refuse(&request);
                    let Ok(size) = u16::try_from(bytes.len()) else { return };
                    if stream.write_all(&size.to_be_bytes()).await.is_err() || stream.write_all(&bytes).await.is_err() {
                        return;
                    }
                    continue;
                }
                stamp(&mut request, peer.ip());
                let Ok(mut response) = client.ask(&request).await else { return };
                response.metadata.id = request.metadata.id;
                let Ok(bytes) = response.to_vec() else { return };
                let Ok(size) = u16::try_from(bytes.len()) else { return };
                if stream.write_all(&size.to_be_bytes()).await.is_err() || stream.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_name_blocks_the_name_and_its_children() {
        let rules = parse_blocks("# kommentar\n*.data.microsoft.com\ntrace.svc.ui.com\n\n");
        assert!(hits(&rules, "data.microsoft.com"));
        assert!(hits(&rules, "v10.events.data.microsoft.com."));
        assert!(hits(&rules, "trace.svc.ui.com"));
        assert!(!hits(&rules, "microsoft.com"));
        assert!(!hits(&rules, "notdata.microsoft.com"));
    }
}
