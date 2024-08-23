use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::{BigInt,PrimeField,UniformRand};
use ark_ec::PrimeGroup;
use std::ops::{Mul,Add,Neg};
use crate::bitvm20::serde_for_coordinate::{serialize_bn254_element,deserialize_bn254_element};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use chrono::Utc;

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

    pub fn sign_transaction(&mut self, private_key : &Fr) {
        // k = random scalar
        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);
        let k : Fr = Fr::rand(&mut prng);

        // R = kG
        let R : G1Projective = G1Projective::generator().mul(k);

        // e = h(Rx || M)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialize_bn254_element(&BigUint::from(G1Affine::from(R).x)));
        hasher.update(&self.serialize_without_signature());
        let data_hash = hasher.finalize();
        let data_hash = data_hash.as_bytes();
        let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

        // s = (k - de) mod N
        let s : Fr = k - (*private_key) * e;

        // R, s is the siganture
        self.r = G1Affine::from(R);
        self.s = s;
    }

    pub fn verify_signature(&self) -> bool {

        // Rv = s * G
        let Rv : G1Projective = G1Projective::generator().mul(self.s);

        // e = h(Rx || M)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialize_bn254_element(&BigUint::from(self.r.x)));
        hasher.update(&self.serialize_without_signature());
        let data_hash = hasher.finalize();
        let data_hash = data_hash.as_bytes();
        let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

        // R - Rv == e * P
        return G1Projective::from(self.r).add(Rv.neg()) == self.from_public_key.mul(e);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_bigint::{BigUint};
    use ark_ff::BigInt;

    #[test]
    fn test_bitvm20_transaction_signature_verify() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);

        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invaliud"));

        assert!(!tx.verify_signature(), "signature verification for unsigned transaction not failing as expected");

        tx.sign_transaction(&from_private_key);

        let is_valid = tx.verify_signature();
        
        assert!(is_valid, "test failed signature logic (signing or verification) incorrect");
        println!("signature verified !!!");
    }
}