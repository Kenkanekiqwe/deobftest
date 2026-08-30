use deobf::core::{pack, unpack};

#[test]
fn roundtrip_container() {
    let source = b"DEOBF container test payload";
    let mut encoded = Vec::new();
    let info = pack(&mut encoded, source).unwrap();
    assert_eq!(info.version, 3);
    assert_eq!(info.original_size, source.len() as u64);

    let (decoded_info, decoded) = unpack(encoded.as_slice()).unwrap();
    assert_eq!(decoded_info, info);
    assert_eq!(decoded, source);
}

#[test]
fn detects_tampering() {
    let mut encoded = Vec::new();
    pack(&mut encoded, b"integrity").unwrap();
    *encoded.last_mut().unwrap() ^= 1;
    assert!(unpack(encoded.as_slice()).is_err());
}
