use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

struct Job {
    message: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
}

pub struct Pool {
    senders: Vec<mpsc::Sender<Job>>,
    addresses: Vec<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Pool {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Pool {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            senders: Vec::new(),
            addresses: Vec::new(),
            tasks: Vec::new(),
        })
    }

    pub async fn start(addresses: &[SocketAddr]) -> Arc<Self> {
        let mut senders = Vec::new();
        let mut tasks = Vec::new();
        let mut usable = Vec::new();
        for address in addresses {
            let Ok(socket) = bind_udp(*address) else { continue };
            let (tx, rx) = mpsc::channel(256);
            tasks.push(tokio::spawn(drive(*address, socket, rx)));
            senders.push(tx);
            usable.push(*address);
        }
        Arc::new(Self {
            senders,
            addresses: usable,
            tasks,
        })
    }

    pub async fn resolve(&self, query: &Message) -> Result<Message, ()> {
        let expect = query.queries.first().cloned().ok_or(())?;
        let bytes = query.to_vec().map_err(|_| ())?;
        let mut set = tokio::task::JoinSet::new();
        for sender in &self.senders {
            let sender = sender.clone();
            let message = bytes.clone();
            let expect = expect.clone();
            set.spawn(async move {
                let (tx, rx) = oneshot::channel();
                sender.send(Job { message, reply: tx }).await.map_err(|_| ())?;
                let packet = timeout(Duration::from_secs(2), rx).await.map_err(|_| ())?.map_err(|_| ())?;
                accepted(&packet, &expect).ok_or(())
            });
        }
        let mut truncated = None;
        while let Some(joined) = set.join_next().await {
            let Ok(Ok(message)) = joined else { continue };
            if message.metadata.truncation {
                truncated = Some(message);
                continue;
            }
            set.abort_all();
            return Ok(message);
        }
        if let Some(message) = self.tcp(&expect, &bytes).await? {
            return Ok(message);
        }
        truncated.ok_or(())
    }

    async fn tcp(&self, expect: &Query, bytes: &[u8]) -> Result<Option<Message>, ()> {
        for address in &self.addresses {
            if let Some(message) = query_tcp(*address, bytes, expect).await {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }
}

async fn drive(address: SocketAddr, socket: UdpSocket, mut jobs: mpsc::Receiver<Job>) {
    let mut pending: HashMap<u16, oneshot::Sender<Vec<u8>>> = HashMap::new();
    let mut next = 1u16;
    let mut buffer = vec![0u8; 4096];
    loop {
        if pending.len() > 32 {
            pending.retain(|_, sender| !sender.is_closed());
        }
        tokio::select! {
            job = jobs.recv() => {
                let Some(job) = job else { break };
                if job.message.len() < 12 { continue; }
                let id = loop {
                    next = next.wrapping_add(1);
                    if next == 0 { next = 1; }
                    if !pending.contains_key(&next) { break next; }
                };
                let mut message = job.message;
                message[0] = (id >> 8) as u8;
                message[1] = (id & 0xff) as u8;
                if socket.send_to(&message, address).await.is_ok() {
                    pending.insert(id, job.reply);
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((size, _)) = received else { break };
                if size < 12 { continue; }
                let id = u16::from_be_bytes([buffer[0], buffer[1]]);
                if let Some(sender) = pending.remove(&id) {
                    let _ = sender.send(buffer[..size].to_vec());
                }
            }
        }
    }
}

async fn query_tcp(address: SocketAddr, query: &[u8], expect: &Query) -> Option<Message> {
    let mut query = query.to_vec();
    let id = 0x4e21u16;
    query[0] = (id >> 8) as u8;
    query[1] = (id & 0xff) as u8;
    let connect = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(address)).await.ok()?.ok()?;
    let mut stream = connect;
    let length = u16::try_from(query.len()).ok()?;
    timeout(Duration::from_secs(3), async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&query).await?;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        let size = u16::from_be_bytes(head) as usize;
        if size > 65535 {
            return Err(std::io::Error::other("Antwort ist zu groß"));
        }
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await?;
        Ok(body)
    })
    .await
    .ok()?
    .ok()
    .and_then(|body| accepted(&body, expect))
}

fn accepted(packet: &[u8], expect: &Query) -> Option<Message> {
    let message = Message::from_vec(packet).ok()?;
    if message.metadata.message_type != MessageType::Response {
        return None;
    }
    if let Some(query) = message.queries.first() {
        if query.name != expect.name || query.query_type != expect.query_type {
            return None;
        }
    }
    Some(message)
}

fn bind_udp(address: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if address.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    let local: SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    socket.bind(&local.into())?;
    UdpSocket::from_std(socket.into())
}
