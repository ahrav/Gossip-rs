use gossip_contracts::identity::{
    CanonicalBytes, FindingId, OccurrenceId, TenantId, TenantSecretKey,
};

// --- Size-only check (TenantSecretKey is restricted, no ZERO sentinel) ------
gossip_contracts::smoke_test_id_size!(TenantSecretKey, 32);

#[test]
fn tenant_secret_key_roundtrip() {
    let bytes = [0xAB; 32];
    let key = TenantSecretKey::from_bytes(bytes);
    assert_eq!(*key.as_bytes(), bytes);
}

#[test]
fn tenant_secret_key_debug_is_safe() {
    let key = TenantSecretKey::from_bytes([0xFF; 32]);
    let dbg = format!("{key:?}");
    assert_eq!(dbg, "TenantSecretKey([redacted])");
    assert!(!dbg.contains("ff"));
}

#[test]
fn canonical_bytes_trait_usable() {
    fn assert_canonical<T: CanonicalBytes>() {}
    assert_canonical::<FindingId>();
    assert_canonical::<OccurrenceId>();
    assert_canonical::<TenantId>();
}
