use num_bigint::{BigUint};
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::{BigInt,PrimeField};
use ark_ec::PrimeGroup;
use std::ops::Mul;
use crate::bitvm20::serde_for_coordinate::{serialize_g1affine,deserialize_g1affine};
use crate::bitvm20::serde_for_uint::{serialize_256bit_biguint,serialize_u64,deserialize_256bit_biguint,deserialize_u64};

pub const bitvm20_entry_serialized_size : usize = (36 + 36 + 8 + 32);

#[derive(PartialEq, Debug)]
pub struct bitvm20_entry {
    pub public_key : G1Affine, // x, y of the public key
    pub nonce : u64, // 64 bit nonce to be serialized in little endian format
    pub balance : BigUint, // 256 bit unsigned integer to be serialized in little endian format
}

pub const default_bitvm20_entry : bitvm20_entry = bitvm20_entry {
    public_key: G1Affine::new_unchecked(Fq::new(BigInt::zero()), Fq::new(BigInt::zero())),
    nonce: 0,
    balance: BigUint::ZERO,
};

impl bitvm20_entry {

    pub fn new(private_key : &Fr, nonce: u64, balance: &BigUint) -> bitvm20_entry {
        return bitvm20_entry {
            public_key: G1Affine::from(G1Projective::generator().mul(private_key)),
            nonce: nonce,
            balance: balance.clone(),
        }
    }

    // serialized form of the bitvm20_entry
    pub fn serialize(&self) -> [u8; bitvm20_entry_serialized_size] {
        let mut result : [u8; bitvm20_entry_serialized_size] = [0; bitvm20_entry_serialized_size];
        result[0..72].copy_from_slice(&serialize_g1affine(&self.public_key));
        result[72..80].copy_from_slice(&serialize_u64(self.nonce));
        result[80..112].copy_from_slice(&serialize_256bit_biguint(&self.balance));
        return result;
    }

    pub fn deserialize(data : &[u8; bitvm20_entry_serialized_size]) -> bitvm20_entry {
        let result = bitvm20_entry {
            public_key: deserialize_g1affine(&data[0..72]),
            nonce: deserialize_u64(&data[72..80]),
            balance: deserialize_256bit_biguint(&data[80..112]),
        };
        return result;
    }

    // blake3 hash of the serialized bitvm20_entry
    pub fn hash(&self) -> [u8; 32] {
        let serialized = self.serialize();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialized);
        let data_hash = hasher.finalize();
        return *data_hash.as_bytes();
    }
}

impl Clone for bitvm20_entry {
    fn clone(&self) -> bitvm20_entry {
        return bitvm20_entry{
            public_key: self.public_key.clone(),
            nonce: self.nonce,
            balance: self.balance.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::UniformRand;
    use chrono::Utc;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn test_bitvm20_entry_serde() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let x1 = bitvm20_entry::new(&Fr::rand(&mut prng), 0x523456789abcdefa, &BigUint::parse_bytes(b"1a5aa55ababaef123456789abcdeffedcba987654321f123456789abcdeba987", 16).expect("failure to parse balance"));
        let s = x1.serialize();
        let x2 = bitvm20_entry::deserialize(&s);
        println!("{:#?}", x1);
        println!("{:#?}", x2);
        assert!((x1 == x2), "test failed, x1 != x2, bug in serializer or deserializer");
        println!("x1 == x2 -> {}", (x1 == x2));
    }
}