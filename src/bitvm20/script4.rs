use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits};

use crate::signatures::winternitz::PublicKey;

// leaves signum(a - b) on the stack
// <0 -> a < b
// =0 -> a = b
// >0 -> a > b
fn compare_32_byte_numbers(a : usize, b : usize) -> Script {
    script! {
        // push current result, initially 0 to alt stack
        OP_0
        OP_TOALTSTACK
        for i in 0..32 {
            // create a duplicate result to stack
            OP_FROMALTSTACK
            OP_DUP

            // compare it with 0
            OP_0
            OP_EQUAL
            OP_IF

                OP_DROP // drop previous result, being 0

                // pick the relevant limbs and substract them
                {b + 31 - i} OP_PICK
                {a + 32 - i} OP_PICK
                OP_SUB
                OP_TOALTSTACK

            OP_ELSE // result is non zero, push the +1, or -1, back to alt stack

                OP_TOALTSTACK
            
            OP_ENDIF
        }

        // pop result back from altstack
        OP_FROMALTSTACK
    }
}

fn generate_sum_carry(a : usize, b : usize) -> Script {
    script! {
        OP_0 OP_TOALTSTACK // pushing the 0 carry

        for i in 0..32 {
            {a + i} OP_PICK
            {b + i + 1} OP_PICK
            OP_ADD
            OP_FROMALTSTACK // bring carry to the stack
            OP_ADD  // add carry
            {0xff} OP_GREATERTHAN
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
    }
}

// inputs are value (32 bytes), to-entry balance (32 bytes), from-entry balance (32 bytes), from-entry nonce (8 bytes)
pub fn construct_script4(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 40 + 32 + 32) }

        // LOGIC STARTS HERE

        // initialize the number of checks passed
        OP_0 OP_TOALTSTACK
        
        // balance of the to-entry user will not overflow, on adding value
        {generate_sum_carry(0, 32)}
        OP_0 OP_EQUAL
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

        // balance of the from-entry user must be greater than or equal to value
        {compare_32_byte_numbers(0, 64)}
        OP_0 OP_GREATERTHANOREQUAL
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

        // count the number of limbs of the nonce that equal 0xff
        OP_0 OP_TOALTSTACK
        for i in 0..8 {
            {96+i} OP_PICK
            {0xff} OP_EQUAL
            OP_FROMALTSTACK
            OP_ADD
            OP_TOALTSTACK
        }
        OP_FROMALTSTACK {8} OP_EQUAL OP_NOT
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

        OP_FROMALTSTACK {3} OP_EQUAL OP_NOT

        // pop the input data from the stack
        OP_TOALTSTACK
        { pop_bytes(40 + 32 + 32) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bitvm20::{bitvm20_entry::bitvm20_entry, bitvm20_merkel_tree::bitvm20_merkel_tree};
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,sign_digits};
    use ark_bn254::{Fq, G1Affine};
    use num_traits::Zero;
    use crate::signatures::winternitz::N;
    use std::ops::Add;
    use ark_ff::BigInt;
    use num_bigint::BigUint;

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script4() {
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);

        let mut mt = bitvm20_merkel_tree::new();
        
        for i in 0..32 {
            mt.assign(bitvm20_entry{
                public_key: G1Affine::new_unchecked(Fq::new(BigInt::new([(i+25) as u64; 4])), Fq::new(BigInt::new([(i+26) as u64; 4]))),
                nonce: ((i + 400) * 13) as u64,
                balance: BigUint::zero().add(1000000000u64),
            });
        }

        let tx = mt.generate_transaction(3, 4, &BigUint::zero().add(1000000u64)).unwrap();

        let validation_result = mt.primary_validate_transaction(&tx);
        assert!(validation_result, "rust offchain basic transaction validation did not pass1");

        // generate 1018 privet keys
        let mut winternitz_private_keys = vec![];
        for _ in 0..1 {
            winternitz_private_keys.push(String::from(winternitz_private_key));
        }

        let (validation_result, exec_contexts) = mt.generate_scripts_for_primary_validation_of_transaction(&tx, &winternitz_private_keys, &[[[0 as u8; 20]; N as usize]; 0], &[script!{}; 0]);
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