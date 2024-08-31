use bitcoin::opcodes::all::{OP_BOOLOR, OP_ENDIF, OP_FROMALTSTACK, OP_TOALTSTACK};

use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits, reorder_blake3_output_for_le_bytes};

use crate::signatures::winternitz::PublicKey;

use crate::hash::blake3::blake3_var_length;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// inputs are serialized form of Rx from signature, bitvm20_transaction (without signature) and then e, in that order
// evaluates if e != blake3(Rx || bitvm20_transaction)
pub fn construct_script5_1(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 36 + 184 + 36) }

        // LOGIC STARTS HERE

        { blake3_var_length(220) } // hash (Rx || tx-without the signature attributes)

        // the below Fr::from_hash call requires us to rever the output of the blake3_var_length
        // do not make the mistake of calling reorder_blake3_output_for_le_bytes()
        for i in 0..32 {
            {i} OP_ROLL
        }
        { Fr::from_hash() }

        { Fr::toaltstack() } // push generated e to the stack

        { U254::from_bytes() } // convert input e to its Fr form

        { Fr::fromaltstack() } // now both the e (generated and the input) are on the stack

        { Fr::equal(1, 0) } // compare them both

        OP_NOT // release funds, if they are not equal
    }
}

// compare if top 2 G1Affine elements of the stack are equal
fn G1Affine_equal() -> Script {
    script! {
        OP_0 OP_TOALTSTACK
        { Fq::roll(2) }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_ADD
        {2} OP_EQUAL
    }
}

// inputs are serialized form of (Pi+1, Pi, Ri, i, s in bits 0 to 253, Ri-1)
// evaulates false || (Pi+1 != 2 * Pi) || (Ri != Ri-1 + s[i] * Pi)
// 2 sets of parameters for evaulating e*P and s*G
pub fn construct_script5_2(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

        OP_0 OP_TOALTSTACK

        // Pi+1 to its G1Affine form, and push it to alt stack
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::toaltstack() }

        // Pi to its G1Affine form
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }

        // Pi to its G1Projective
        { G1Affine::into_projective() }

        // clone Pi
        { G1Projective::copy(0) }

        // now we have 2 Pi on the top of the stack, in its G1Projective form 

        // implement inquality 1
        { G1Projective::double() }
        { G1Projective::into_affine() }
        { Fq::fromaltstack() }
        { Fq::fromaltstack() }
        { G1Affine_equal() }
        OP_NOT OP_FROMALTSTACK OP_BOOLOR

        // now the stack contents are 
        // Pi Projective, Ri, i, s, Ri-1
        { G1Projective::toaltstack() }
        // convert Ri to G1Affine
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        // bring Pi back to the stack
        { G1Projective::fromaltstack() }
        // bring Ri as G1 Affine to the to top of the stack, and Pi projective right behind it
        { Fq::roll(4) }
        { Fq::roll(4) }
        // push both of them to the altstack
        { Fq::toaltstack() }{ Fq::toaltstack() }
        { G1Projective::toaltstack() }

        // now the top of the stack are i and then bits of s starting with 0
        OP_ROLL // fetch the ith bit
        // drop the rest of the 253 bits
        OP_TOALTSTACK
        for _ in 0..253 {
            OP_DROP
        }
        // bring the ith bit of s back from the altstack
        OP_FROMALTSTACK

        // if this bit is 1, make stack top to be Ri-1 + Pi
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        OP_IF
            { G1Affine::into_projective() }
            { G1Projective::fromaltstack() }
            { G1Projective::add() }
            { G1Projective::into_affine() }
        OP_ELSE
            { G1Projective::fromaltstack() }
            { G1Projective::drop() }
        OP_ENDIF

        // bring Ri from its affine from, from the altstack
        { Fq::fromaltstack() } { Fq::fromaltstack() }

        // inequality 2
        { G1Affine_equal() }
        OP_NOT OP_FROMALTSTACK OP_BOOLOR
    }
}

// inputs are serialized form of (R, s*G, e*P)
// evauates R - s * G != e * P
pub fn construct_script5_3(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

    }
}
/*
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

    #[test]
    fn test_bitvm20_script5_partitioned() {
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
            "script 5 size:\n \t{:?} bytes",
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
*/