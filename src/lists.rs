use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

const SKIP: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
];

const LOCAL_IPS: &[&str] = &[
    "0.0.0.0",
    "127.0.0.1",
    "::",
    "::1",
    "255.255.255.255",
    "0.0.0.0/0",
];

pub fn extract(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for raw in text.lines() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(domain) = rest.split(['^', '$', '|']).next().and_then(clean) {
                found.insert(domain);
            }
            continue;
        }
        if let Some(index) = line.find('#') {
            line = line[..index].trim();
        }
        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else { continue };
        let names: Vec<&str> = if LOCAL_IPS.contains(&first) {
            parts.collect()
        } else {
            vec![first]
        };
        for name in names {
            if let Some(domain) = clean(name) {
                found.insert(domain);
            }
        }
    }
    found
}

fn clean(raw: &str) -> Option<String> {
    let mut name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_prefix("*.") {
        name = rest.trim_matches('.').to_string();
    }
    if name.is_empty()
        || SKIP.contains(&name.as_str())
        || !name.contains('.')
        || name.len() > 253
        || name.contains([' ', '/', ':', '#', '*'])
    {
        return None;
    }
    Some(name)
}

pub fn load_file(path: &Path) -> BTreeSet<String> {
    fs::read_to_string(path)
        .map(|text| extract(&text))
        .unwrap_or_default()
}

pub fn save_file(path: &Path, domains: &BTreeSet<String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut text = domains.iter().cloned().collect::<Vec<_>>().join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    fs::write(path, text)
}

pub fn download(url: &str) -> Result<String, String> {
    if !url.starts_with("https://") || url.len() > 400 {
        return Err("Liste braucht eine https-Adresse.".into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(45))
        .build();
    let response = agent
        .get(url)
        .set("User-Agent", "dns-server")
        .call()
        .map_err(|error| match error {
            ureq::Error::Status(404, _) => "Liste wurde nicht gefunden.".into(),
            other => {
                let detail = other.to_string();
                let lower = detail.to_ascii_lowercase();
                if lower.contains("timed out") || lower.contains("timeout") {
                    "Zeitüberschreitung beim Laden.".into()
                } else if detail.contains("404") {
                    "Liste wurde nicht gefunden.".into()
                } else {
                    detail
                }
            }
        })?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(80_000_001)
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    if body.len() > 80_000_000 {
        return Err("Sperrliste ist zu groß.".into());
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hosts_adblock_and_plain_domains() {
        let text = "\
# comment
0.0.0.0 localhost ads.example
||tracker.example^$third-party
plain.example
! title
";
        let found = extract(text);
        assert!(found.contains("ads.example"));
        assert!(found.contains("tracker.example"));
        assert!(found.contains("plain.example"));
        assert!(!found.contains("localhost"));
    }
}
