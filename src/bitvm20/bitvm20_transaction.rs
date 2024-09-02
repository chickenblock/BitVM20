use num_bigint::BigUint;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::{BigInt, BigInteger, PrimeField, UniformRand};
use ark_ec::{AffineRepr, PrimeGroup};
use std::ops::{Mul,Add,Neg};
use crate::bitvm20::serde_for_coordinate::{serialize_bn254_element,deserialize_bn254_element};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry};
use crate::bitvm20::bitvm20_execution_context::{bitvm20_execution_context};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use chrono::Utc;

use crate::treepp::{script, Script};
use crate::bitvm20::script5_partitioned::{construct_script5_1, construct_script5_2, construct_script5_3, construct_script5_4};
use crate::signatures::winternitz::{generate_public_key,PublicKey};

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
        result[184..220].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.r.y), true));
        result[220..256].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.r.x), true));
        result[256..292].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.s), false));
        return result;
    }

    pub fn serialize_without_signature(&self) -> [u8; 184] {
        let mut result : [u8; 184] = [0; 184];
        let mut i : usize = 0;
        result[0..36].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.from_public_key.y), true));i+=36;
        result[36..72].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.from_public_key.x), true));i+=36;
        result[72..108].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.to_public_key.y), true));i+=36;
        result[108..144].copy_from_slice(&serialize_bn254_element(&BigUint::from(self.to_public_key.x), true));i+=36;
        while i < 152 {
            result[i] = ((self.from_nonce >> ((i-144)*8)) & 0xff) as u8; i+=1;
        }
        let temp = self.value.to_bytes_le();
        while i < 184 && (i-152) < temp.len() {
            result[i] = temp[i-152]; i+=1;
        }
        return result;
    }

    pub fn deserialize_without_signature(data : &[u8]) -> bitvm20_transaction {
        let mut result : bitvm20_transaction = bitvm20_transaction {
            from_public_key: G1Affine::new_unchecked(
                                Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[36..72], true).to_bytes_le())),
                                Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[0..36], true).to_bytes_le()))
                            ),
            to_public_key: G1Affine::new_unchecked(
                                Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[108..144], true).to_bytes_le())),
                                Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[72..108], true).to_bytes_le()))
                            ),
            from_nonce: 0,
            value: BigUint::from_bytes_le(&data[152..184]),
            r: G1Affine::new_unchecked(Fq::new(BigInt::zero()), Fq::new(BigInt::zero())),
            s: Fr::new(BigInt::zero()),
        };
        for i in (144..152) {
            result.from_nonce |= ((data[i] as u64) << ((i-144)*8));
        }
        return result;
    }

    pub fn deserialize(data : &[u8]) -> bitvm20_transaction {
        let mut result = bitvm20_transaction::deserialize_without_signature(data);
        result.r = G1Affine::new_unchecked(
            Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[220..256], true).to_bytes_le())),
            Fq::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[184..220], true).to_bytes_le()))
        );
        result.s = Fr::from_le_bytes_mod_order(&(deserialize_bn254_element(&data[256..292], false).to_bytes_le()));
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

    pub fn generate_execution_contexts_for_signature_verification(&self, winternitz_private_keys : &[String], winternitz_public_keys : &[PublicKey], winternitz_signatures : &[Script]) -> Vec<bitvm20_execution_context> {
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
                result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_1(&generate_public_key(&winternitz_private_keys[result.len()]))));
            } else {
                result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_1(&winternitz_public_keys[result.len()])));
            }
        }

        // construct eP = e * P
        let mut eP = G1Projective::from(G1Affine::zero());
        {
            let mut power_i = G1Projective::from(self.from_public_key);
            for i in 0..254 {
                let mut eP_next = eP.clone();
                if(e.into_bigint().get_bit(i) == true) {
                    eP_next = eP_next.add(power_i);
                }
                let power_i_next = power_i.add(power_i);

                // script for eP_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP_next).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP_next).x), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).x), true));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(e), false));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP).x), true));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_2(&generate_public_key(&winternitz_private_keys[result.len()]))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_2(&winternitz_public_keys[result.len()])));
                    }
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i_next).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i_next).x), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).x), true));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_3(&generate_public_key(&winternitz_private_keys[result.len()]))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_3(&winternitz_public_keys[result.len()])));
                    }
                }

                eP_next = eP;
                power_i = power_i_next;
            }
        }

        // construct Rv = s * G
        let mut Rv = G1Projective::from(G1Affine::zero());
        {
            let mut power_i = G1Projective::generator();
            for i in 0..254 {
                let mut Rv_next = Rv.clone();
                if(self.s.into_bigint().get_bit(i) == true) {
                    Rv_next = Rv_next.add(power_i);
                }
                let power_i_next = power_i.add(power_i);

                // script for Rv_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv_next).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv_next).x), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).x), true));
                    input.push(i as u8);
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(self.s), false));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv).x), true));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_2(&generate_public_key(&winternitz_private_keys[result.len()]))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_2(&winternitz_public_keys[result.len()])));
                    }
                }

                // script for power_i_next
                {
                    let mut input = vec![];
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i_next).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i_next).x), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).y), true));
                    input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(power_i).x), true));
                    if(winternitz_private_keys.len() > 0) {
                        result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_3(&generate_public_key(&winternitz_private_keys[result.len()]))));
                    } else {
                        result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_3(&winternitz_public_keys[result.len()])));
                    }
                }

                Rv_next = Rv;
                power_i = power_i_next;
            }
        }

        // build script for R - Rv == eP
        {
            let mut input = vec![];
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(self.r).y), true));
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(self.r).x), true));
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv).y), true));
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(Rv).x), true));
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP).y), true));
            input.extend_from_slice(&serialize_bn254_element(&BigUint::from(G1Affine::from(eP).x), true));
            if(winternitz_private_keys.len() > 0) {
                result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, &construct_script5_4(&generate_public_key(&winternitz_private_keys[result.len()]))));
            } else {
                result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], &construct_script5_4(&winternitz_public_keys[result.len()])));
            }
        }

        return result;
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

        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
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