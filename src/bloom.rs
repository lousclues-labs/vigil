//! BLAKE3-derived Bloom filter for fast event path rejection.
//!
//! Inserted at startup from watch paths. The monitor checks each event path
//! against the filter before forwarding to workers. False positives reach
//! workers (harmless); false negatives cannot occur.

/// Uses BLAKE3-derived hash functions for probabilistic membership testing.
pub struct BloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: u32,
}

impl BloomFilter {
    /// Create a new Bloom filter sized for `expected_items` with the given
    /// false positive rate.
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let expected_items = expected_items.max(1);
        let fp = false_positive_rate.clamp(1e-10, 1.0);

        // Optimal number of bits: m = -(n * ln(p)) / (ln(2)^2)
        let num_bits =
            (-(expected_items as f64 * fp.ln()) / (2.0_f64.ln().powi(2))).ceil() as usize;
        let num_bits = num_bits.max(64);

        // Optimal number of hash functions: k = (m/n) * ln(2)
        let num_hashes = ((num_bits as f64 / expected_items as f64) * 2.0_f64.ln()).ceil() as u32;
        let num_hashes = num_hashes.clamp(1, 16);

        let byte_len = num_bits.div_ceil(8);

        Self {
            bits: vec![0u8; byte_len],
            num_bits,
            num_hashes,
        }
    }

    /// Insert an item into the Bloom filter.
    pub fn insert(&mut self, item: &[u8]) {
        let hash = blake3::hash(item);
        let hash_bytes = hash.as_bytes();

        for i in 0..self.num_hashes {
            let idx = self.get_bit_index(hash_bytes, i);
            self.bits[idx / 8] |= 1 << (idx % 8);
        }
    }

    /// Check if an item might be in the Bloom filter.
    /// Returns `false` if the item is definitely not in the set.
    /// Returns `true` if the item might be in the set (with some false positive probability).
    pub fn might_contain(&self, item: &[u8]) -> bool {
        let hash = blake3::hash(item);
        let hash_bytes = hash.as_bytes();

        for i in 0..self.num_hashes {
            let idx = self.get_bit_index(hash_bytes, i);
            if self.bits[idx / 8] & (1 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Derive the k-th bit index from the BLAKE3 hash output.
    /// Uses double hashing: h(i) = (h1 + i * h2) mod m
    fn get_bit_index(&self, hash_bytes: &[u8; 32], k: u32) -> usize {
        let h1 = u64::from_le_bytes([
            hash_bytes[0],
            hash_bytes[1],
            hash_bytes[2],
            hash_bytes[3],
            hash_bytes[4],
            hash_bytes[5],
            hash_bytes[6],
            hash_bytes[7],
        ]);
        let h2 = u64::from_le_bytes([
            hash_bytes[8],
            hash_bytes[9],
            hash_bytes[10],
            hash_bytes[11],
            hash_bytes[12],
            hash_bytes[13],
            hash_bytes[14],
            hash_bytes[15],
        ]);

        (h1.wrapping_add(h2.wrapping_mul(k as u64)) % self.num_bits as u64) as usize
    }

    /// Check if any prefix of the given path might be in the Bloom filter.
    /// Walks path components and checks each prefix; if any prefix matches,
    /// the event should pass through (not be rejected).
    pub fn might_contain_prefix_of(&self, path: &std::path::Path) -> bool {
        let mut prefix = std::path::PathBuf::new();
        for component in path.components() {
            prefix.push(component);
            if self.might_contain(prefix.as_os_str().as_encoded_bytes()) {
                return true;
            }
        }
        false
    }

    /// Build a Bloom filter from watch path prefixes.
    /// Inserts all path component prefixes for each watch path.
    pub fn from_watch_paths(watch_paths: &[std::path::PathBuf]) -> Self {
        // Estimate total items: paths * average depth
        let total_components: usize = watch_paths.iter().map(|p| p.components().count()).sum();
        let expected = total_components.max(10);

        let mut bloom = Self::new(expected, 0.01);

        for path in watch_paths {
            let mut prefix = std::path::PathBuf::new();
            for component in path.components() {
                prefix.push(component);
                bloom.insert(prefix.as_os_str().as_encoded_bytes());
            }
        }

        bloom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn no_false_negatives() {
        let mut bloom = BloomFilter::new(100, 0.01);

        let items: Vec<&[u8]> = vec![b"/etc", b"/etc/passwd", b"/usr/bin", b"/usr/bin/ls"];

        for item in &items {
            bloom.insert(item);
        }

        // All inserted items must be found (zero false negative rate)
        for item in &items {
            assert!(
                bloom.might_contain(item),
                "false negative for {:?}",
                std::str::from_utf8(item)
            );
        }
    }

    #[test]
    fn false_positive_rate_below_threshold() {
        let mut bloom = BloomFilter::new(1000, 0.01);

        // Insert 1000 items
        for i in 0..1000u32 {
            let item = format!("/path/to/item/{}", i);
            bloom.insert(item.as_bytes());
        }

        // Test 10000 non-inserted items
        let mut false_positives = 0u32;
        for i in 1000..11000u32 {
            let item = format!("/other/path/{}", i);
            if bloom.might_contain(item.as_bytes()) {
                false_positives += 1;
            }
        }

        let fp_rate = false_positives as f64 / 10000.0;
        assert!(fp_rate < 0.05, "false positive rate {} too high", fp_rate);
    }

    #[test]
    fn from_watch_paths_includes_prefixes() {
        let paths = vec![PathBuf::from("/etc/ssh"), PathBuf::from("/usr/bin")];

        let bloom = BloomFilter::from_watch_paths(&paths);

        // All prefixes should be in the filter
        assert!(bloom.might_contain(b"/etc"));
        assert!(bloom.might_contain(b"/etc/ssh"));
        assert!(bloom.might_contain(b"/usr"));
        assert!(bloom.might_contain(b"/usr/bin"));

        // Unrelated paths should likely not be found
        // (could be false positive, but unlikely with so few entries)
        assert!(!bloom.might_contain(b"/var/log"));
    }

    #[test]
    fn bloom_fast_reject_for_fanotify() {
        // Simulate the fanotify event loop fast-reject logic
        let paths = vec![
            PathBuf::from("/etc/ssh"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/boot"),
        ];
        let bloom = BloomFilter::from_watch_paths(&paths);

        // Paths under watched directories should pass the Bloom filter
        // (the Bloom filter stores prefixes, so /etc and /etc/ssh are inserted)
        assert!(bloom.might_contain(b"/etc"));
        assert!(bloom.might_contain(b"/etc/ssh"));
        assert!(bloom.might_contain(b"/usr/bin"));
        assert!(bloom.might_contain(b"/boot"));

        // A path like /home/user/file.txt should be rejected
        // (no prefix path "/home" or "/home/user" was inserted)
        assert!(!bloom.might_contain(b"/home/user/file.txt"));
        assert!(!bloom.might_contain(b"/home"));

        // /proc, /sys, /dev should also be rejected since they aren't watched
        assert!(!bloom.might_contain(b"/proc/1/status"));
        assert!(!bloom.might_contain(b"/sys/class"));
    }
}
