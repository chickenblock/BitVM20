use crate::treepp::{script, Script};

use crate::hash::sha256::sha256;

use crate::signatures::winternitz::checksig_verify;
use crate::signatures::winternitz::generate_public_key;

fn duplicate_32_byte_numbers(a : usize) -> Script {
    script! {
        for _ in 0..32 {
            {a + 31} OP_PICK
        }
    }
}

// leaves signum(a - b) on the stack
// <0 -> a < b
//  0 -> a = b
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
            {0xff} OP_LESSTHAN
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
    }
}

// inputs are from-entry nonce and balance (8 + 32 = 40 bytes), to-entry balance (32 bytes), value (32 bytes) and its signatures (i.e. hashes generated by sign_digits), in that order
// addresses from top => value -> 0, to-entry balance -> 32, from-entry balance -> 64, from-entry nonce -> 96
pub fn construct_script4(winternitz_private_key: &str) -> Script {

    let public_key = generate_public_key(winternitz_private_key);

    script!{
        { checksig_verify(&public_key) }
        // now we have the 20 bytes of the sha256 hash that was signed by the winternitz signatures

        // reverse these 20 bytes, and push each of these to altstack
        for i in 0..20 {
            {19 - i} OP_ROLL OP_TOALTSTACK
        }

        // find 32 byte sha256 hash of the (40 + 32 + 32) byte data on the stack, drop its first (32-20) excess bytes
        { sha256(40 + 32 + 32) }
        for i in 0..(32-20) {
            OP_DROP
        }

        // compare both the hashes, if compare fails we quit with failure
        for i in 0..20 {
            OP_FROMALTSTACK
            OP_EQUALVERIFY
        }

        // LOGIC STARTS HERE

        // initialize the number of checks passed
        OP_0 OP_TOALTSTACK
        
        // balance of the to-entry user will not overflow, on adding value
        {generate_sum_carry(0, 32)}
        OP_0 OP_EQUAL
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK

        // balance of the from-entry user must be greater than or equal to value
        {compare_32_byte_numbers(0, 64)}
        OP_0 OP_LESSTHANOREQUAL
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
    }
}