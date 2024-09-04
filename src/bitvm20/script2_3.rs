use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits,reorder_blake3_output_for_le_bytes};

use crate::signatures::winternitz::PublicKey;

use crate::hash::blake3::{blake3,blake3_var_length};

use crate::bitvm20::bitvm20_merkel_tree::{levels,bitvm20_merkel_tree_size};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry_serialized_size};

// inputs are merkel proof (12 levels) {entry_index_bit(levels-1), ... entry_index_bit1, entry_index_bit0, entry, sibling_levels ... sibling2, sibling1, root} in bytes ((levels+1) * 32 + 74 + levels)
pub fn construct_script2_3(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, (levels+1) * 32 + bitvm20_entry_serialized_size + levels ) }

        // LOGIC STARTS HERE

        // move entry index to alt stack, hash the entry
        for _ in 0..levels {
            OP_TOALTSTACK
        }
        { blake3_var_length(bitvm20_entry_serialized_size) }
        { reorder_blake3_output_for_le_bytes() }
        
        // iterate for levels number of types
        for _ in (1..=levels).rev() {
            OP_FROMALTSTACK
            OP_IF
                // swap the last 2, 32 byte elements
                for _ in 0..32 {
                    {63} OP_ROLL
                }
            OP_ENDIF
            { blake3() } // 64 byte blake3
            { reorder_blake3_output_for_le_bytes() } // hash in reverse order
        }

        // compare the last 2 remaining roots
        // only returns true if lesser than 32 limbs are equal
        OP_0 OP_TOALTSTACK
        for i in 0..32 {
           {32-i} OP_ROLL OP_EQUAL
           OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        {32} OP_EQUAL OP_NOT
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,N};
    use num_bigint::{BigUint};
    use crate::bitvm20::bitvm20_entry::bitvm20_entry;
    use crate::bitvm20::bitvm20_merkel_tree::{bitvm20_merkel_tree,bitvm20_merkel_proof};
    use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
    use ark_ff::BigInt;

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script2_3() {
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);
        println!(
            "script 2_3 size:\n \t{:?} bytes",
            construct_script2_3(&winternitz_public_key).len()
        );

        let mut mt = bitvm20_merkel_tree::new();
        for i in 0..bitvm20_merkel_tree_size {
            mt.assign(bitvm20_entry{
                public_key: G1Affine::new_unchecked(Fq::new(BigInt::new([(i+24) as u64; 4])), Fq::new(BigInt::new([(i+24) as u64; 4]))),
                nonce: ((i + 400) * 13) as u64,
                balance: BigUint::from_bytes_be(&[(((i + 13) * 13) & 0xff) as u8; 10]),
            });
        }

        // generate proof for 10-th entry
        let p = mt.generate_proof(0xa);
        assert!(!p.is_none(), "Generated none proof");
        let proof = p.unwrap();

        // generate 1018 privet keys
        let mut winternitz_private_keys = vec![];
        for _ in 0..1 {
            winternitz_private_keys.push(String::from(winternitz_private_key));
        }

        let (validation_result, exec_contexts) = proof.generate_execution_contexts_for_merkel_proof_validation(&winternitz_private_keys, &[[[0 as u8; 20]; N as usize]; 0], &[script!{}; 0]);
        assert!(validation_result, "rust offchain basic transaction validation did not pass2");

        println!("generated execution contexts");

        for (i, ec) in exec_contexts.iter().enumerate() {
            let s = ec.get_executable();
            println!("script no. {} of size {}\n", i, ec.get_script().len());
            //println!("input : {:x?}\n", ec.input_parameters);
            run(script!{
                { s }
                OP_NOT
            });
        }
    }
}