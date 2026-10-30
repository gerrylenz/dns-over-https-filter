use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::engine::{App, Transport};

pub fn spawn_admin(listener: TcpListener, app: Arc<App>) {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let app = app.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let app = app.clone();
                    async move { Ok::<_, Infallible>(admin(app, request).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

pub fn spawn_doh(listener: TcpListener, config: Arc<ServerConfig>, app: Arc<App>) {
    let acceptor = TlsAcceptor::from(config);
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else { return };
                let protocol = stream.get_ref().1.alpn_protocol().map(|value| value.to_vec());
                let service = service_fn(move |request| {
                    let app = app.clone();
                    async move { Ok::<_, Infallible>(doh(app, peer, request).await) }
                });
                let io = TokioIo::new(stream);
                if protocol.as_deref() == Some(b"h2".as_ref()) {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                } else {
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                }
            });
        }
    });
}

async fn admin(app: Arc<App>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    if method == http::Method::GET {
        return match path.as_str() {
            "/" | "/index.html" => asset("index.html", "text/html; charset=utf-8", INDEX),
            "/app.js" => asset("app.js", "text/javascript; charset=utf-8", SCRIPT),
            "/app.css" => asset("app.css", "text/css; charset=utf-8", STYLE),
            "/favicon.ico" => empty(StatusCode::NO_CONTENT),
            "/api/state" => json(StatusCode::OK, app.snapshot()),
            _ => empty(StatusCode::NOT_FOUND),
        };
    }
    if method != http::Method::POST {
        return empty(StatusCode::METHOD_NOT_ALLOWED);
    }
    if path == "/api/refresh" {
        app.ask_refresh();
        return json(StatusCode::OK, serde_json::json!({"ok": true}));
    }
    if path == "/api/token" {
        return match app.rotate_token() {
            Ok(token) => json(StatusCode::OK, serde_json::json!({"ok": true, "token": token})),
            Err(error) => json(StatusCode::BAD_REQUEST, serde_json::json!({"ok": false, "error": error})),
        };
    }
    if path != "/api/config" {
        return empty(StatusCode::NOT_FOUND);
    }
    let bytes = match body(request, 1_000_000).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let patch = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return json(StatusCode::BAD_REQUEST, serde_json::json!({"ok": false, "error": "Anfrage ist ungültig."}))
        }
    };
    match app.update_config(patch).await {
        Ok(()) => json(StatusCode::OK, serde_json::json!({"ok": true})),
        Err(error) => json(StatusCode::BAD_REQUEST, serde_json::json!({"ok": false, "error": error})),
    }
}

async fn doh(app: Arc<App>, peer: SocketAddr, request: Request<Incoming>) -> Response<Full<Bytes>> {
    if !app.token_matches(request.uri().path()) {
        return empty(StatusCode::NOT_FOUND);
    }
    let packet = if request.method() == http::Method::GET {
        let Some(query) = request.uri().query() else {
            return empty(StatusCode::BAD_REQUEST);
        };
        let Some(value) = query.split('&').find_map(|item| item.strip_prefix("dns=")) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        match decode_dns(value) {
            Some(packet) => packet,
            None => return empty(StatusCode::BAD_REQUEST),
        }
    } else if request.method() == http::Method::POST {
        let kind = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if kind != "application/dns-message" {
            return empty(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        match body(request, 65535).await {
            Ok(bytes) if !bytes.is_empty() => bytes.to_vec(),
            _ => return empty(StatusCode::BAD_REQUEST),
        }
    } else {
        return empty(StatusCode::METHOD_NOT_ALLOWED);
    };
    let Some(reply) = app.handle_packet(&packet, peer.ip(), Transport::Doh).await else {
        return empty(StatusCode::BAD_REQUEST);
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(reply)))
        .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
}

async fn body(request: Request<Incoming>, limit: usize) -> Result<Bytes, Response<Full<Bytes>>> {
    Limited::new(request.into_body(), limit)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|_| json(StatusCode::BAD_REQUEST, serde_json::json!({"ok": false, "error": "Anfrage ist ungültig."})))
}

fn decode_dns(value: &str) -> Option<Vec<u8>> {
    let value = value.replace('-', "+").replace('_', "/");
    let mut padded = value;
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    base64::engine::general_purpose::STANDARD.decode(padded).ok()
}

fn asset(name: &str, content_type: &str, embedded: &str) -> Response<Full<Bytes>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static").join(name);
    let bytes = std::fs::read(path).unwrap_or_else(|_| embedded.as_bytes().to_vec());
    Response::builder()
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(value.to_string())))
        .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

const INDEX: &str = include_str!("../static/index.html");
const SCRIPT: &str = include_str!("../static/app.js");
const STYLE: &str = include_str!("../static/app.css");
