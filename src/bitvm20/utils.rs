use crate::treepp::{script, Script};

use crate::hash::blake3::blake3_var_length;

use crate::signatures::winternitz::checksig_verify;
use crate::signatures::winternitz::PublicKey;

pub fn data_to_signable_balke3_digits(data : &Vec<u8>) -> [u8; 40] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&data);
    let data_hash = hasher.finalize();
    let data_hash = data_hash.as_bytes();
    let mut signable_digits : [u8; 40] = [0; 40];
    for i in 0..20 {
        signable_digits[2*i] = data_hash[12+i] & 0xf;
        signable_digits[2*i+1] = data_hash[12+i] >> 4;
    }
    return signable_digits;
}

// output of blake3 is bit unorderly
// this function will reorder it to match the outputs of most official implementations
pub fn reorder_blake3_output_for_le_bytes() -> Script {
    script! {
        for i in 0..32 {
            {(((i/4)+1)*4)-1} OP_ROLL
        }
    }
}

// utility function to verify the input data to any of the bitvm20 scripts
pub fn verify_input_data(winternitz_public_key: &PublicKey, data_size: usize) -> Script {
    script! {
        { checksig_verify(&winternitz_public_key) }
        // now we have the 20 bytes of the balake3 hash that was signed by the winternitz signatures

        // reverse these 20 bytes, and push each of these to altstack
        for i in 0..20 {
            {19 - i} OP_ROLL OP_TOALTSTACK
        }

        // duplicate data_size bytes of data
        for _ in 0..data_size {
            {data_size-1} OP_PICK
        }

        // find 32 byte blake3 hash of the data_size bytes of data on the stack
        { blake3_var_length(data_size) }
        { reorder_blake3_output_for_le_bytes() }

        // drop its first (32-20) excess bytes
        { pop_bytes(32-20) }

        // compare both the hashes, if compare fails we quit with failure
        for i in 0..20 {
            OP_FROMALTSTACK
            OP_EQUALVERIFY
        }
    }
}

pub fn pop_bytes(data_size : usize) -> Script {
    script! {
        for _ in 0..(data_size/2) {
            OP_2DROP
        }
        if data_size % 2 == 1 {
            OP_DROP
        }
    }
}