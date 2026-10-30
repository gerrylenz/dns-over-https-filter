use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};

use crate::config::Settings;

pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn ensure(settings: &mut Settings, directory: &Path) -> Result<(PathBufWrap, PathBufWrap), String> {
    let cert = directory.join("tls.crt");
    let key = directory.join("tls.key");
    let missing = !cert.is_file() || !key.is_file();
    let renamed = settings.cert_hostname != settings.hostname;
    if settings.self_signed && (missing || renamed) {
        generate(&settings.hostname, &cert, &key)?;
        settings.cert_hostname = settings.hostname.clone();
    }
    if !cert.is_file() || !key.is_file() {
        return Err("Zertifikat fehlt. tls.crt und tls.key neben die Konfiguration legen.".into());
    }
    Ok((PathBufWrap(cert), PathBufWrap(key)))
}

pub struct PathBufWrap(pub std::path::PathBuf);

fn generate(hostname: &str, cert: &Path, key: &Path) -> Result<(), String> {
    if let Some(parent) = cert.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let pair = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])
        .map_err(|error| error.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let certificate = params
        .self_signed(&pair)
        .map_err(|error| error.to_string())?;
    std::fs::write(cert, certificate.pem()).map_err(|error| error.to_string())?;
    std::fs::write(key, pair.serialize_pem()).map_err(|error| error.to_string())?;
    Ok(())
}

pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let mut reader = BufReader::new(File::open(cert).map_err(|error| error.to_string())?);
    let chain: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(File::open(key).map_err(|error| error.to_string())?);
    let private = private_key(&mut reader)
        .map_err(|error| error.to_string())?
        .ok_or("Privater Schlüssel fehlt.")?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .map_err(|error| error.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
