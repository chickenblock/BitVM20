use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits};

use crate::signatures::winternitz::PublicKey;

// inputs are previous merkel state root in bytes
pub fn construct_script1(winternitz_public_key: &PublicKey, original_merkel_state_root : Vec<u8>) -> Script {
    script!{
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
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::run;
    use crate::signatures::winternitz::{generate_public_key,sign_digits};
    use crate::hash::blake3::*;

    // The secret key
    const winternitz_private_key: &str = "b138982ce17ac813d505b5b40b665d404e9528e7";

    #[test]
    fn test_bitvm20_script1() {
        // The message to sign
        #[rustfmt::skip]

        let winternitz_public_key = generate_public_key(winternitz_private_key);

        // merkel root to be compared against
        let merkel_root: Vec<u8> = vec![0x01, 0x02, 0x0a, 0x0b, 0x11, 0x12, 0x2a, 0x2b,
                                    0x31, 0x03, 0x3a, 0x03, 0x44, 0x14, 0x24, 0xfb,
                                    0xa1, 0x02, 0xba, 0xcb, 0x1e, 0xd2, 0xea, 0x2f,
                                    0x31, 0xa3, 0xba, 0x0c, 0x44, 0xe4, 0xff, 0xfb];
        
        let signable_hash_digits : [u8; 40] = data_to_signable_balke3_digits(&merkel_root);

        println!("merkel_root : {:x?}", merkel_root);
        println!("signable_hash_digits : {:x?}", signable_hash_digits);

        let script = script! {
            for x in (&merkel_root).iter().rev() {
                {(*x)}
            }
            { sign_digits(winternitz_private_key, signable_hash_digits) }
            { construct_script1(&winternitz_public_key, merkel_root.clone()) }
        };

        println!(
            "script 1 size:\n \t{:?} bytes",
            script.len(),
        );

        run(script! {
            for x in (&merkel_root).iter().rev() {
                {(*x)}
            }
            { sign_digits(winternitz_private_key, signable_hash_digits) }
            { construct_script1(&winternitz_public_key, merkel_root.clone()) }

            OP_0 OP_EQUAL // on correct execution this script must fail
        });
    }
}