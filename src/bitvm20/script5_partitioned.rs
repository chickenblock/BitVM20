use bitcoin::opcodes::all::{OP_BOOLAND, OP_BOOLOR, OP_ENDIF, OP_FROMALTSTACK, OP_TOALTSTACK};

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

pub fn G1Projective_equal() -> Script {
    script! {
        OP_1 OP_TOALTSTACK // initialize result stack

        { Fq::copy(3) }
        { Fq::square() }
        { Fq::roll(4) }
        { Fq::copy(1) }
        { Fq::mul() }

        { Fq::copy(2) }
        { Fq::square() }
        { Fq::roll(3) }
        { Fq::copy(1) }
        { Fq::mul() }

        { Fq::roll(7) }
        { Fq::roll(2) }
        { Fq::mul() }
        { Fq::roll(5) }
        { Fq::roll(4) }
        { Fq::mul() }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK // and the output of equal with the result

        { Fq::roll(3) }
        { Fq::roll(1) }
        { Fq::mul() }
        { Fq::roll(2) }
        { Fq::roll(2) }
        { Fq::mul() }
        { Fq::equal(1, 0) }
        OP_FROMALTSTACK OP_BOOLAND // and the output of equal with the result, and leave result on the stack
    }
}

// inputs are serialized form of (Ri, Pi, i, s, Ri-1)
// evaulates (Ri != Ri-1 + s[i] * Pi)
pub fn construct_script5_2(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 36 * 2 + 36 * 2 + 1 + 36 + 36 * 2) }

        // LOGIC STARTS HERE

        // Ri to its G1Affine form, then to its G1Projective and push it to alt stack
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
        { G1Projective::toaltstack() }

        // Pi to its G1Affine form, then to its G1Projective and push it to alt stack
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
        { G1Projective::toaltstack() }

        // now the top of the stack are i and then s and then Ri-1
        OP_TOALTSTACK
        { U254::from_bytes() }
        { Fr::convert_to_le_bits() }
        OP_FROMALTSTACK
        OP_ROLL // fetch the ith bit
        // drop the rest of the 253 bits
        OP_TOALTSTACK
        for _ in 0..253 {
            OP_DROP
        }

        // now the top of the alt stack is s[i]
        // and top of the stack is Ri-1 in bytes

        // convert Ri-1 into its projective from
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }

        OP_FROMALTSTACK // bring s[i] to the stack
        OP_IF
            { G1Projective::fromaltstack() }
            { G1Projective::add() }
        OP_ELSE
            { G1Projective::fromaltstack() }
            { G1Projective::drop() }
        OP_ENDIF

        // bring Ri from its affine from, from the altstack
        { G1Projective::fromaltstack() }

        // compare
        { G1Projective_equal() }
        OP_NOT
    }
}

// inputs are serialized form of (Pi+1, Pi)
// evaulates (Pi+1 != 2 * Pi)
pub fn construct_script5_3(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 36 * 2 + 36 * 2) }

        // LOGIC STARTS HERE

        // Pi+1 to its G1Affine form, then into its G1Projective form and push it to alt stack
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
        { G1Projective::toaltstack() }

        // Pi to its G1Affine form, then into its G1Projective form
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }

        // double Pi
        { G1Projective::double() }

        // bring Pi+1 to the stack
        { G1Projective::fromaltstack() }

        // compare both Pi+1 and Pi * 2
        { G1Projective_equal() }
        OP_NOT
    }
}

// inputs are serialized form of (R, s*G, e*P)
// evauates R - s * G != e * P
pub fn construct_script5_4(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 36 * 2 + 36 * 2 + 36 * 2) }

        // LOGIC STARTS HERE

        // convert R into into its G1Affine and then into G1Projective from, and push it to altstack
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
        { G1Projective::toaltstack() }

        // convert s * G into its G1Affine and them into G1Projective form, and then negate it
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }
        { G1Projective::neg() }

        // add the R + (-s*G)
        { G1Projective::fromaltstack() }
        { G1Projective::add() }
        { G1Projective::toaltstack() }

        // convert e*P into its G1Affine form, and then into G1Projective
        { U254::from_bytes() }
        { Fq::toaltstack() }
        { U254::from_bytes() }
        { Fq::fromaltstack() }
        { G1Affine::into_projective() }

        // now move the addition result to the stack and compare it
        { G1Projective::fromaltstack() }

        // compare them
        { G1Projective_equal() }
        OP_NOT
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,sign_digits, N};
    use crate::bitvm20::bitvm20_entry::bitvm20_entry;
    use crate::bitvm20::bitvm20_transaction::bitvm20_transaction;
    use num_bigint::{BigUint,RandomBits};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use chrono::Utc;
    use ark_bn254::{Fr};
    use ark_ff::{BigInt,PrimeField,UniformRand};
    use std::ops::{Add, Mul};

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script5_partitioned() {
        #[rustfmt::skip]

        println!("stats :");
        println!("G1Projective::double : {}", G1Projective::double().len());
        println!("G1Projective::add : {}", G1Projective::add().len());
        println!("G1Projective::into_affine : {}", G1Projective::into_affine().len());
        println!("G1Projective::equalverify : {}", G1Projective::equalverify().len());
        println!("G1Projective_equal : {}", G1Projective_equal().len());

        let winternitz_public_key = generate_public_key(winternitz_private_key);

        println!(
            "script 5 size:\n \t{:?}, {:?}, {:?}, {:?} bytes",
            construct_script5_1(&winternitz_public_key).len(),
            construct_script5_2(&winternitz_public_key).len(),
            construct_script5_3(&winternitz_public_key).len(),
            construct_script5_4(&winternitz_public_key).len()
        );

        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);

        let from_private_key : Fr = Fr::rand(&mut prng);
        let from : bitvm20_entry = bitvm20_entry::new(&from_private_key, 0x0123, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid from balance"));
        let to : bitvm20_entry = bitvm20_entry::new(&Fr::rand(&mut prng), 0x3456, &BigUint::parse_bytes(b"1000000000", 10).expect("invalid to balance"));

        let mut tx = bitvm20_transaction::new_unsigned(&from, &to, &BigUint::parse_bytes(b"5000", 10).expect("transfer value invalid"));
        tx.sign_transaction(&from_private_key);
        assert!(tx.verify_signature(), "rust offchain signature verification did not pass");

        // generate 1018 privet keys
        let mut winternitz_private_keys = vec![];
        for _ in 0..1018 {
            winternitz_private_keys.push(String::from(winternitz_private_key));
        }

        let exec_contexts = tx.generate_execution_contexts_for_signature_verification(&winternitz_private_keys, &[[[0 as u8; 20]; N as usize]; 0], &[script!{}; 0]);

        for ec in exec_contexts {
            run(ec.get_executable());
        }
    }

    use ark_ec::CurveGroup;
    #[test]
    fn test_projective_equal() {
        let equal = G1Projective_equal();
        println!("G1.equalverify: {} bytes", equal.len());

        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..1 {
            let scalar = Fr::rand(&mut prng);

            let p = ark_bn254::G1Projective::rand(&mut prng).mul(scalar);
            let q = p.into_affine();

            let script = script! {
                { Fq::push_u32_le(&BigUint::from(p.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.y).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(p.z).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.x).to_u32_digits()) }
                { Fq::push_u32_le(&BigUint::from(q.y).to_u32_digits()) }
                { Fq::push_one() }
                { equal.clone() }
            };
            println!("curves::test_equalverify = {} bytes", script.len());
            run(script);
        }
    }
}
