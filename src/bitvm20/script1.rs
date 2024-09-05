use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data};

use crate::signatures::winternitz::PublicKey;

// inputs are previous merkel state root in bytes
pub fn construct_script1(winternitz_public_key: &PublicKey, original_merkel_state_root : &Vec<u8>) -> Script {
    assert!(original_merkel_state_root.len() == 32, "merkel state root is not 32 bytes");
    return script!{
        { verify_input_data(&winternitz_public_key, 32) }

        // LOGIC STARTS HERE
        
        // comparing the original_merkel_state_root with the one provided in data
        // only returns true if lesser than 32 limbs are equal
        OP_0 OP_TOALTSTACK
        for i in 0..32 {
            {original_merkel_state_root[i]} OP_EQUAL
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        {32} OP_EQUAL OP_NOT
    };
}

#[cfg(test)]
mod test {
    use ark_bn254::{Fq, G1Affine};
    use ark_ff::BigInt;
    use num_bigint::BigUint;

    use super::*;
    use crate::bitvm20::bitvm20_entry::bitvm20_entry;
    use crate::bitvm20::bitvm20_merkel_tree::{bitvm20_merkel_tree, bitvm20_merkel_tree_size};
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key, ZeroPublicKey};

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script1() {
        // The message to sign
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);
        println!(
            "script 1 size:\n \t{:?} bytes",
            construct_script1(&winternitz_public_key, &vec![0xffu8; 32]).len()
        );

        let mut mt = bitvm20_merkel_tree::new();
        for i in 0..bitvm20_merkel_tree_size {
            mt.assign(bitvm20_entry{
                public_key: G1Affine::new_unchecked(Fq::new(BigInt::new([(i+24) as u64; 4])), Fq::new(BigInt::new([(i+24) as u64; 4]))),
                nonce: ((i + 400) * 13) as u64,
                balance: BigUint::from_bytes_be(&[(((i + 13) * 13) & 0xff) as u8; 10]),
            });
        }

        let winternitz_private_keys = vec![String::from(winternitz_private_key); 1];

        let exec_contexts = mt.generate_execution_contexts_for_merkel_root_validation(&winternitz_private_keys, &[ZeroPublicKey; 0], &[script!{}; 0]);

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