use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::BigInt;
use crate::bitvm20::serde_for_coordinate::{serialize_bn254_element,deserialize_bn254_element};

struct bitvm20_transaction {
    from_public_key: G1Affine,
    to_public_key: G1Affine,
    value: BigUint,
    from_nonce: u64,

    // signature attributes
    r: G1Affine, // rx and ry, both in little endian form
    s: Fr,
}