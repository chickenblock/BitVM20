use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::BigInt;
use crate::bitvm20::serde_for_coordinate::{serialize_bn254_element,deserialize_bn254_element};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry};

struct bitvm20_transaction {
    from_public_key: G1Affine,
    to_public_key: G1Affine,
    from_nonce: u64,
    value: BigUint,

    // signature attributes
    r: G1Affine,
    s: Fr,
}

impl bitvm20_transaction {
    pub fn new(from: &bitvm20_entry, to: &bitvm20_entry, value: &BigUint, r: &G1Affine, s: &Fr) -> bitvm20_transaction {
        return bitvm20_transaction {
            from_public_key: from.public_key.clone(),
            to_public_key: to.public_key.clone(),
            from_nonce: from.nonce,
            value: value.clone(),
            r: r.clone(),
            s: s.clone(),
        }
    }

    pub fn new_unsigned(from: &bitvm20_entry, to: &bitvm20_entry, value: &BigUint) -> bitvm20_transaction {
        return Self::new(from, to, value, &G1Affine::new_unchecked(Fq::new(BigInt::zero()), Fq::new(BigInt::zero())), &Fr::new(BigInt::zero()));
    }

    pub fn serialize(&self) -> [u8; 292] {
        let mut result : [u8; 292] = [0; 292];
        result[0..184].copy_from_slice(&self.serialize_without_signature());
        result[184..220].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.r.y)));
        result[220..256].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.r.x)));
        result[256..292].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.s)));
        return result;
    }

    pub fn serialize_without_signature(&self) -> [u8; 184] {
        let mut result : [u8; 184] = [0; 184];
        let mut i : usize = 0;
        result[0..36].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.from_public_key.y)));i+=36;
        result[36..72].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.from_public_key.x)));i+=36;
        result[72..108].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.to_public_key.y)));i+=36;
        result[108..144].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.to_public_key.x)));i+=36;
        while i < 152 {
            result[i] = ((self.from_nonce >> (i-144)) & 0xff) as u8; i+=1;
        }
        let temp = self.value.to_bytes_le();
        while i < 184 && (i-152) < temp.len() {
            result[i] = temp[i-152]; i+=1;
        }
        return result;
    }

    pub fn sign_transactions(&mut self) {

    }

    pub fn verify_signature(&self) -> bool {
        return false;
    }
}