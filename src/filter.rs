use std::collections::HashMap;
use std::net::IpAddr;

/// A domain stored leftmost label first: `www`, `example`, `com`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Domain {
    labels: Vec<Box<[u8]>>,
}

impl Domain {
    pub fn parse(raw: &str) -> Option<Self> {
        let ascii = ascii_name(raw)?;
        let labels: Vec<Box<[u8]>> = ascii
            .split('.')
            .filter(|label| !label.is_empty())
            .map(|label| label.as_bytes().to_vec().into_boxed_slice())
            .collect();
        if labels.is_empty() || labels.iter().any(|label| label.len() > 63) {
            return None;
        }
        if labels.iter().map(|label| label.len() + 1).sum::<usize>() > 254 {
            return None;
        }
        Some(Self { labels })
    }

    pub fn as_str(&self) -> String {
        self.labels
            .iter()
            .map(|label| std::str::from_utf8(label).unwrap_or(""))
            .collect::<Vec<_>>()
            .join(".")
    }

    fn tld(&self) -> Option<&[u8]> {
        self.labels.last().map(|label| label.as_ref())
    }

    fn is_under(&self, suffix: &Domain) -> bool {
        self.labels.len() > suffix.labels.len()
            && self.labels[self.labels.len() - suffix.labels.len()..] == suffix.labels[..]
    }
}

fn ascii_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.contains("..") {
        return None;
    }
    if name.is_ascii()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return Some(name);
    }
    idna::domain_to_ascii(&name).ok()
}

const SPECIAL: &[&[u8]] = &[
    b"local",
    b"localhost",
    b"invalid",
    b"test",
    b"onion",
    b"home",
    b"lan",
    b"internal",
    b"alt",
];

pub fn is_special(domain: &Domain) -> bool {
    domain
        .tld()
        .is_some_and(|tld| SPECIAL.iter().any(|item| *item == tld))
}

#[derive(Default)]
struct Node {
    children: HashMap<Box<[u8]>, Node>,
    terminal: bool,
}

#[derive(Default)]
pub struct Trie {
    root: Node,
    len: usize,
}

impl Trie {
    pub fn insert(&mut self, domain: &Domain) {
        let mut node = &mut self.root;
        for label in domain.labels.iter().rev() {
            node = node.children.entry(label.clone()).or_default();
        }
        if !node.terminal {
            node.terminal = true;
            self.len += 1;
        }
    }

    pub fn contains(&self, domain: &Domain) -> bool {
        let mut node = &self.root;
        let mut hit = false;
        for label in domain.labels.iter().rev() {
            match node.children.get(label.as_ref()) {
                Some(next) => {
                    node = next;
                    hit |= node.terminal;
                }
                None => return hit,
            }
        }
        hit
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

#[derive(Clone, Debug)]
pub struct Rewrite {
    pub name: String,
    pub address: IpAddr,
    pub wildcard: bool,
}

#[derive(Default)]
pub struct Filter {
    pub block: Trie,
    pub deny: Trie,
    pub allow: Trie,
    exact: HashMap<Domain, IpAddr>,
    wildcards: Vec<(Domain, IpAddr)>,
}

impl Filter {
    pub fn insert_rewrite(&mut self, rule: Rewrite) {
        let Some(domain) = Domain::parse(&rule.name) else {
            return;
        };
        if rule.wildcard {
            self.wildcards.push((domain, rule.address));
            self.wildcards
                .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.labels.len()));
        } else {
            self.exact.insert(domain, rule.address);
        }
    }

    pub fn rewrite(&self, domain: &Domain) -> Option<IpAddr> {
        if let Some(address) = self.exact.get(domain) {
            return Some(*address);
        }
        self.wildcards
            .iter()
            .find(|(suffix, _)| domain.is_under(suffix))
            .map(|(_, address)| *address)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Local {
    Rewrite(IpAddr),
    Special,
    Allowed,
    Blocked,
    Forward,
}

pub fn classify(filter: &Filter, paused: bool, domain: &Domain) -> Local {
    if let Some(address) = filter.rewrite(domain) {
        return Local::Rewrite(address);
    }
    if is_special(domain) {
        return Local::Special;
    }
    if filter.allow.contains(domain) {
        return Local::Allowed;
    }
    if !paused && (filter.deny.contains(domain) || filter.block.contains(domain)) {
        return Local::Blocked;
    }
    Local::Forward
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_domain_blocks_children_only() {
        let mut trie = Trie::default();
        trie.insert(&Domain::parse("ads.example").unwrap());
        assert!(trie.contains(&Domain::parse("ads.example").unwrap()));
        assert!(trie.contains(&Domain::parse("a.ads.example").unwrap()));
        assert!(!trie.contains(&Domain::parse("example").unwrap()));
        assert!(!trie.contains(&Domain::parse("other.example").unwrap()));
    }

    #[test]
    fn wildcard_rewrite_skips_the_apex() {
        let mut filter = Filter::default();
        filter.insert_rewrite(Rewrite {
            name: "intern.lan".into(),
            address: "10.0.0.1".parse().unwrap(),
            wildcard: true,
        });
        let host = Domain::parse("drucker.intern.lan").unwrap();
        let apex = Domain::parse("intern.lan").unwrap();
        assert_eq!(filter.rewrite(&host), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(filter.rewrite(&apex), None);
    }

    #[test]
    fn allow_beats_a_block_and_local_names_stay_local() {
        let mut filter = Filter::default();
        filter.block.insert(&Domain::parse("ads.example").unwrap());
        filter.allow.insert(&Domain::parse("ads.example").unwrap());
        assert_eq!(
            classify(&filter, false, &Domain::parse("a.ads.example").unwrap()),
            Local::Allowed
        );
        assert_eq!(
            classify(&filter, false, &Domain::parse("drucker.lan").unwrap()),
            Local::Special
        );
    }
}
