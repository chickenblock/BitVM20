use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits, reorder_blake3_output_for_le_bytes};

use crate::signatures::winternitz::PublicKey;

use crate::hash::blake3::blake3_var_length;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// inputs are serialized form of bitvm20_transaction, in that order
pub fn construct_script5(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

        // generate P
        // clone serialized form of from_public_key (which is at the top of the stack), convert it to G1Affine, then to G1PRojective and then push it to the alt stack, as is
        for _ in (0..72) {
            {71} OP_PICK
        }
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of P on the stack
        { G1Affine::into_projective() } // convert G1Affine P to G1Projective P
        { G1Projective::toaltstack() } // push P back to alt stack
        
        // generate e = h(Rx || M)
        for _ in (0..36) {// copy Rx to the top of ths stack giving ud Rx || tx on the stack
            {255} OP_PICK
        }
        { blake3_var_length(220) } // hash (Rx || tx-without the singature attributes)
        { reorder_blake3_output_for_le_bytes() }
        { Fr::from_hash() }

        // now e is at the top if the stack
        { G1Projective::fromaltstack() } // pop G1Projective P to the top of the stack
        { Fr::roll(3) } // bring e to the top of the stack, and P right under it
        { G1Projective::scalar_mul() } // egenerate eP = e * P
        { G1Projective::toaltstack() } // push eP to alt stack

        // now the top of the stack is signature r, we will convert it to G1Projective R
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of R on the stack
        { G1Affine::into_projective() } // convert G1Affine R to G1Projective R
        { G1Projective::toaltstack() } // push R back to alt stack

        // now the top of the stack is signature s
        { U254::from_bytes() } // s into its Fr form
        { Fr::toaltstack() } // push s to alt stack

        // push generator on the stack G
        { G1Projective::push_generator() }
        { Fr::fromaltstack() } // bring s back to the stack

        // produce Rv = s * G
        { G1Projective::scalar_mul() }

        // produce R - Rv
        { G1Projective::neg() } // top of the stack is Rv, so first negate it
        { G1Projective::fromaltstack() } // now the stack contains :: -Rv Rv <- top
        { G1Projective::add() } // add them

        // convert R - Rv to G1Affine
        { G1Projective::into_affine() }

        // move eP to the stack, and convert it to affine
        { G1Projective::fromaltstack() }
        { G1Projective::into_affine() }

        DEBUG

        // check that they are unequal
        OP_0 OP_TOALTSTACK
        { Fq::roll(2) }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_ADD
        {2} OP_EQUAL OP_NOT
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,sign_digits};
    use crate::bitvm20::bitvm20_entry::bitvm20_entry;
    use crate::bitvm20::bitvm20_transaction::bitvm20_transaction;
    use num_bigint::{BigUint,RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use chrono::Utc;
    use ark_bn254::{Fr};
    use ark_ff::{BigInt,PrimeField,UniformRand};

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    /*use crate::bitvm20::serde_for_coordinate::serialize_bn254_element;
    //use ark_ff::{BigInt,PrimeField,UniformRand};
    use ark_ec::PrimeGroup;
    use std::ops::{Mul,Add,Neg};
    #[test]
    fn test_temp() {
        #[rustfmt::skip]

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);
        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0x0123, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0x3456, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invalid"));
        tx.sign_transaction(&from_private_key);
        assert!(tx.verify_signature(), "rust offchain signature verification did not pass");

        let t = ark_bn254::G1Affine::from(ark_bn254::G1Projective::generator().mul(tx.s));

        println!("t = {:0x?}, {:0x?}\n", serialize_bn254_element(&BigUint::from((t.y)), true), serialize_bn254_element(&BigUint::from((t.x)), true));

        let s = script! {
            { G1Projective::push_generator() }
            for x in (&serialize_bn254_element(&BigUint::from(tx.s), false)).iter().rev() {
                {(*x)}
            }
            { U254::from_bytes() }
            { G1Projective::scalar_mul() }
            { G1Projective::into_affine() }
            for x in (&serialize_bn254_element(&BigUint::from(t.x), true)).iter().rev() {
                {(*x)}
            }
            { U254::from_bytes() }
            for x in (&serialize_bn254_element(&BigUint::from(t.y), true)).iter().rev() {
                {(*x)}
            }
            { U254::from_bytes() }
            { G1Affine::equalverify() }
            OP_TRUE
        };

        println!("script length : {}", s.len());

        run(s)
    }*/

    #[test]
    fn test_bitvm20_script5() {
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);
        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0x0123, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0x3456, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invalid"));
        tx.sign_transaction(&from_private_key);
        assert!(tx.verify_signature(), "rust offchain signature verification did not pass");

        let mut data: Vec<u8> = vec![];
        for d in tx.serialize() {
            data.push(d);
        }

        let signable_hash_digits : [u8; 40] = data_to_signable_balke3_digits(&data);

        println!("data : {:x?}", data);
        println!("signable_hash_digits : {:x?}", signable_hash_digits);

        let script = script! {
            for x in (&data).iter().rev() {
                {(*x)}
            }
            { sign_digits(winternitz_private_key, signable_hash_digits) }
            { construct_script5(&winternitz_public_key) }
        };

        println!(
            "script 4 size:\n \t{:?} bytes",
            script.len(),
        );

        run(script! {
            for x in (&data).iter().rev() {
                {(*x)}
            }
            { sign_digits(winternitz_private_key, signable_hash_digits) }
            { construct_script5(&winternitz_public_key) }

            OP_0 OP_EQUAL // on correct execution this script must fail
        });
    }
}