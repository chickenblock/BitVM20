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
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,sign_digits};
    use num_bigint::{BigUint,RandomBits};

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script4() {
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);

        let value : BigUint =        BigUint::parse_bytes(b"1000000000", 10).expect("failed to parse value");
        let to_balance : BigUint =   BigUint::parse_bytes(b"1157920892", 10).expect("failed to parse to_balance");
        let from_balance : BigUint = BigUint::parse_bytes(b"1000000000", 10).expect("failed to parse from_balance");
        let from_nonce : u64 = 0xfffffffffffffffe;

        let mut data: Vec<u8> = vec![];
        let temp = value.to_bytes_le();
        for i in 0..32 {
            if i < temp.len() {
                data.push(temp[i]);
            }
            else {
                data.push(0x00);
            }
        }
        let temp = to_balance.to_bytes_le();
        for i in 0..32 {
            if i < temp.len() {
                data.push(temp[i]);
            }
            else {
                data.push(0x00);
            }
        }
        let temp = from_balance.to_bytes_le();
        for i in 0..32 {
            if i < temp.len() {
                data.push(temp[i]);
            }
            else {
                data.push(0x00);
            }
        }
        let mut temp = from_nonce;
        for _ in 0..8 {
            data.push((temp & 0xff) as u8);
            temp >>= 8;
        }

        let signable_hash_digits : [u8; 40] = data_to_signable_balke3_digits(&data);

        println!("data : {:x?}", data);
        println!("signable_hash_digits : {:x?}", signable_hash_digits);

        let script = script! {
            for x in (&data).iter().rev() {
                {(*x)}
            }
            { sign_digits(winternitz_private_key, signable_hash_digits) }
            { construct_script4(&winternitz_public_key) }
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
            { construct_script4(&winternitz_public_key) }

            OP_0 OP_EQUAL // on correct execution this script must fail
        });
    }
}