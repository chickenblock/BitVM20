use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::{BigInt, BigInteger, PrimeField, UniformRand};
use ark_ec::{AffineRepr, PrimeGroup};
use std::ops::{Mul,Add,Neg};
use crate::bitvm20::serde_for_coordinate::{serialize_g1affine,serialize_fr,deserialize_g1affine,deserialize_fr,serialize_bn254_element};
use crate::bitvm20::serde_for_uint::{serialize_256bit_biguint,serialize_u64,deserialize_256bit_biguint,deserialize_u64};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use chrono::Utc;
use num_traits::Zero;

use crate::treepp::{Script};
use crate::bitvm20::script5_partitioned::{construct_script5_1, construct_script5_2, construct_script5_3, construct_script5_4};
use crate::signatures::winternitz::{PublicKey};
use crate::bitvm20::bitvm20_execution_context::{bitvm20_execution_context,simple_script_generator};

#[derive(PartialEq, Debug)]
pub struct bitvm20_transaction {
    pub from_public_key: G1Affine,
    pub to_public_key: G1Affine,
    pub from_nonce: u64,
    pub value: BigUint,

    // signature attributes
    pub r: G1Affine,
    pub s: Fr,
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

    pub fn pretty_print(&self) {
        println!("from : {:?}", self.from_public_key);
        println!("to : {:?}", self.to_public_key);
        println!("nonce : {:?}", self.from_nonce);
        println!("value : {:?}", self.value);
        println!("r : {:?}", self.r);
        println!("s : {:?}", self.s);
    }

    pub fn new_unsigned(from: &bitvm20_entry, to: &bitvm20_entry, value: &BigUint) -> bitvm20_transaction {
        return Self::new(from, to, value, &G1Affine::new_unchecked(Fq::new(BigInt::zero()), Fq::new(BigInt::zero())), &Fr::new(BigInt::zero()));
    }

    pub fn serialize(&self) -> [u8; 292] {
        let mut result : [u8; 292] = [0; 292];
        result[0..184].copy_from_slice(&self.serialize_without_signature());
        result[184..256].copy_from_slice(&serialize_g1affine(&self.r));
        result[256..292].copy_from_slice(&serialize_fr(&self.s));
        return result;
    }

    pub fn serialize_without_signature(&self) -> [u8; 184] {
        let mut result : [u8; 184] = [0; 184];
        result[0..72].copy_from_slice(&serialize_g1affine(&self.from_public_key));
        result[72..144].copy_from_slice(&serialize_g1affine(&self.to_public_key));
        result[144..152].copy_from_slice(&serialize_u64(self.from_nonce));
        result[152..184].copy_from_slice(&serialize_256bit_biguint(&self.value));
        return result;
    }

    pub fn deserialize_without_signature(data : &[u8]) -> bitvm20_transaction {
        let result : bitvm20_transaction = bitvm20_transaction {
            from_public_key: deserialize_g1affine(&data[0..72]),
            to_public_key: deserialize_g1affine(&data[72..144]),
            from_nonce: deserialize_u64(&data[144..152]),
            value: deserialize_256bit_biguint(&data[152..184]),
            r: G1Affine::zero(),
            s: Fr::zero(),
        };
        return result;
    }

    pub fn deserialize(data : &[u8]) -> bitvm20_transaction {
        let mut result = bitvm20_transaction::deserialize_without_signature(data);
        result.r = deserialize_g1affine(&data[184..256]);
        result.s = deserialize_fr(&data[256..292]);
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
        hasher.update(&serialize_bn254_element(&BigUint::from(G1Affine::from(R).x), true));
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
        hasher.update(&serialize_bn254_element(&BigUint::from(self.r.x), true));
        hasher.update(&self.serialize_without_signature());
        let data_hash = hasher.finalize();
        let data_hash = data_hash.as_bytes();
        let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

        // R - Rv == e * P
        return G1Projective::from(self.r).add(Rv.neg()) == self.from_public_key.mul(e);
    }

    pub fn generate_execution_contexts_for_signature_verification(&self, winternitz_private_keys : &[String], winternitz_public_keys : &[PublicKey], winternitz_signatures : &[Script]) -> (bool, Vec<bitvm20_execution_context>) {
        let mut result = vec![];

        // construct e = h(Rx || M) -> using script 5_1
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialize_bn254_element(&BigUint::from(self.r.x), true));
        hasher.update(&self.serialize_without_signature());
        let data_hash = hasher.finalize();
        let data_hash = data_hash.as_bytes();
        let e : Fr = Fr::from_le_bytes_mod_order(data_hash);

        // push a script for calculation of e
        {
            let mut input = vec![];
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(self.r.x), true));
            input.extend_from_slice(&self.serialize_without_signature());
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(e), false));
            if(winternitz_private_keys.len() > 0) {
                result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_1))));
            } else {
                result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_1))));
            }
        }

        // construct eP = e * P
        let mut eP = G1Projective::zero();
        {
            let mut power_i = G1Projective::from(self.from_public_key);
            for i in 0..254 {
                let mut eP_next = eP.clone();
                if(e.into_bigint().get_bit(i) == true) {
                    eP_next = eP.add(power_i);
                }
                let power_i_next = power_i.add(power_i);

                // script for eP_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_fr(&e));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP)));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_2))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_2))));
                    }
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_3))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_3))));
                    }
                }

                eP = eP_next;
                power_i = power_i_next;
            }
        }
        assert!((eP == self.from_public_key.mul(e)), "wrong eP");

        // construct Rv = s * G
        let mut Rv = G1Projective::zero();
        {
            let mut power_i = G1Projective::generator();
            for i in 0..254 {
                let mut Rv_next = Rv.clone();
                if(self.s.into_bigint().get_bit(i) == true) {
                    Rv_next = Rv.add(power_i);
                }
                let power_i_next = power_i.add(power_i);

                // script for Rv_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_fr(&self.s));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv)));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_2))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_2))));
                    }
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i_next)));
                    input.extend_from_slice(&serialize_g1affine(&G1Affine::from(power_i)));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_3))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_3))));
                    }
                }

                Rv = Rv_next;
                power_i = power_i_next;
            }
        }
        assert!((Rv == G1Projective::generator().mul(self.s)), "wrong Rv");

        // build script for R - Rv == eP
        {
            let mut input = vec![];
            input.extend_from_slice(&serialize_g1affine(&self.r));
            input.extend_from_slice(&serialize_g1affine(&G1Affine::from(Rv)));
            input.extend_from_slice(&serialize_g1affine(&G1Affine::from(eP)));
            if(winternitz_private_keys.len() > 0) {
                result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script5_4))));
            } else {
                result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script5_4))));
            }
        }

        return ((G1Projective::from(self.r).add(Rv.neg()) == eP) , result);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bitvm20_transaction_signature_verify() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);

        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invalid"));

        tx.pretty_print();

        assert!(!tx.verify_signature(), "signature verification for unsigned transaction not failing as expected");

        tx.sign_transaction(&from_private_key);
        tx.pretty_print();

        let is_valid = tx.verify_signature();
        
        assert!(is_valid, "test failed signature logic (signing or verification) incorrect");
        println!("signature verified !!!");
    }

    use super::*;
    use ark_ff::UniformRand;
    use chrono::Utc;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn test_bitvm20_transaction_serde() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);

        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 1215421545, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx1 = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invalid"));
        tx1.sign_transaction(&from_private_key);

        let s = tx1.serialize();

        let tx2 = bitvm20_transaction::deserialize(&s);

        println!("{:#?}", tx1);
        println!("{:#?}", tx2);
        assert!((tx1 == tx2), "test failed, tx1 != tx2, bug in serializer or deserializer");
        println!("tx1 == tx2 -> {}", (tx1 == tx2));
    }
}