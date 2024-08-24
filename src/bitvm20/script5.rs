use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits};

use crate::signatures::winternitz::PublicKey;

use crate::bn254::curves::{G1Affine, G1Projective};
use crate::bn254::fq::Fq;
use crate::bn254::fr::Fr;
use crate::bn254::fp254impl::Fp254Impl;
use crate::bigint::U254;

// inputs are serialized form of bitvm20_transaction, in that order
pub fn construct_script1(winternitz_public_key: &PublicKey) -> Script {
    script!{
        { verify_input_data(&winternitz_public_key, 292) }

        // LOGIC STARTS HERE

        // generate P
        // clone serialized form of from_public_key (which is at the top of the stack), convert it to G1Affine, then to G1PRojective and then push it to the alt stack, as is
        for _ in (0..72) {
            {73} OP_ROLL
        }
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of P on the stack
        { G1Affine::into_projective() } // convert G1Affine P to G1Projective P
        { G1Projective::toaltstack() } // push P back to alt stack
        
        // generate e = h(Rx || M)
    }
}