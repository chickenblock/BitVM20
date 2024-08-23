use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::BigInt;
use crate::bitvm20::serde_for_coordinate::{serialize_bn254_element,deserialize_bn254_element};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry};

struct bitvm20_transaction {
    from_public_key: G1Affine,
    to_public_key: G1Affine,
    value: BigUint,
    from_nonce: u64,

    // signature attributes
    r: G1Affine,
    s: Fr,
}

impl bitvm20_transaction {
    pub fn new(from: &bitvm20_entry, to: &bitvm20_entry, value: &BigUint, r: &G1Affine, s: &Fr) -> bitvm20_transaction {
        return bitvm20_transaction {
            from_public_key: from.public_key.clone(),
            to_public_key: to.public_key.clone(),
            value: value.clone(),
            from_nonce: from.nonce,
            r: r.clone(),
            s: s.clone(),
        }
    }

    pub fn new_unsigned(from: &bitvm20_entry, to: &bitvm20_entry, value: &BigUint) -> bitvm20_transaction {
        return Self::new(from, to, value, &G1Affine::new_unchecked(Fq::new(BigInt::zero()), Fq::new(BigInt::zero())), &Fr::new(BigInt::zero()));
    }
}