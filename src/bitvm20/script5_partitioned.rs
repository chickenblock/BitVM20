use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits, reorder_blake3_output_for_le_bytes};

use crate::signatures::winternitz::PublicKey;

use crate::hash::blake3::blake3_var_length;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// inputs are serialized form of Rx from signature, bitvm20_transaction (without signature) and then e in its Fr form and the winternitz signatures, in that order
// evaluates if e != blake3(Rx || bitvm20_transaction)
pub fn construct_script5_1(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

    }
}

// inputs are serialized form of (Pi+1, Pi, Ri, i, s in bits, Ri-1) (Ri-1, Pi, s in bits, i, Pi+1, Ri), and winternitz signatures in that order
// evaulates false ||  (Pi+1 != 2 * Pi) || (Ri != Ri-1 + s[i] * Pi)
// 2 sets of parameters for evaulating e*P and s*G
pub fn construct_script5_2(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

    }
}

// inputs are serialized form of (R, s*G, e*P) and the winternitz signatures, in that order
// evauates R - s * G != e * P
pub fn construct_script5_3(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

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