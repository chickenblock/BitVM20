use num_bigint::BigUint;

struct bitvm20_transaction {
    from_public_key: [u8; 64],
    to_public_key: [u8; 64],
    value: BigUint,
    from_nonce: u64,

    // signature attributes
    r: [u8; 64], // rx and ry, both in little endian form
}