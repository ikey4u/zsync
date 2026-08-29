use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// Remembers hashes of clips we just applied so a local watcher does not
/// rebroadcast them (the copy/paste echo loop).
pub struct Suppress {
    ttl: Duration,
    max: usize,
    items: HashMap<String, Instant>,
    ring: VecDeque<String>,
}

impl Suppress {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self {
            ttl,
            max: max.max(8),
            items: HashMap::new(),
            ring: VecDeque::new(),
        }
    }

    pub fn add(&mut self, hash: &str) {
        if hash.is_empty() {
            return;
        }
        self.items.insert(hash.to_string(), Instant::now());
        self.ring.push_back(hash.to_string());
        while self.ring.len() > self.max {
            if let Some(old) = self.ring.pop_front() {
                if let Some(t) = self.items.get(&old) {
                    if t.elapsed() > self.ttl {
                        self.items.remove(&old);
                    }
                }
            }
        }
        self.gc();
    }

    pub fn has(&self, hash: &str) -> bool {
        if hash.is_empty() {
            return false;
        }
        if let Some(t) = self.items.get(hash) {
            if t.elapsed() <= self.ttl {
                return true;
            }
        }
        self.ring.iter().any(|h| h == hash)
    }

    fn gc(&mut self) {
        let ttl = self.ttl;
        let in_ring: std::collections::HashSet<&str> =
            self.ring.iter().map(|s| s.as_str()).collect();
        self.items
            .retain(|h, t| t.elapsed() <= ttl || in_ring.contains(h.as_str()));
    }
}

/// Highest applied sequence per origin. Drops replays and stale frames.
#[derive(Default)]
pub struct SeenSeq {
    last: HashMap<String, u64>,
}

impl SeenSeq {
    pub fn accept(&mut self, origin: &str, seq: u64) -> bool {
        match self.last.get(origin) {
            Some(&prev) if seq <= prev => false,
            _ => {
                self.last.insert(origin.to_string(), seq);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppress_echo() {
        let mut s = Suppress::new(Duration::from_secs(5), 32);
        assert!(!s.has("aa"));
        s.add("aa");
        assert!(s.has("aa"));
    }

    #[test]
    fn seq_monotonic() {
        let mut s = SeenSeq::default();
        assert!(s.accept("a", 1));
        assert!(!s.accept("a", 1));
        assert!(!s.accept("a", 0));
        assert!(s.accept("a", 2));
        assert!(s.accept("b", 1));
    }
}
