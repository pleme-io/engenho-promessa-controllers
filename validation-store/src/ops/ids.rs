//! ULID generation — every row that doesn't have a natural PK gets a
//! ULID. Sortable by time (Crockford base32), 26 chars, 128 bits of
//! entropy. Single shape across all entities so query patterns
//! ("findings created in the last hour") work uniformly.

/// Generate a fresh ULID string (Crockford base32). Time-sortable,
/// 26 chars, lexicographic order matches creation order.
#[must_use]
pub fn ulid_string() -> String {
    ulid::Ulid::new().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulid_is_26_chars() {
        let id = ulid_string();
        assert_eq!(id.len(), 26);
    }

    #[test]
    fn ulids_are_unique() {
        let a = ulid_string();
        let b = ulid_string();
        assert_ne!(a, b);
    }

    #[test]
    fn ulids_sort_by_creation_time() {
        let first = ulid_string();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = ulid_string();
        // ULID Crockford base32 encoding sorts lexicographically by
        // timestamp prefix — newer > older.
        assert!(second > first, "expected {second} > {first}");
    }
}
