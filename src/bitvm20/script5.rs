use crate::treepp::{script, Script};

use crate::bitvm20::utils::{verify_input_data,pop_bytes,data_to_signable_balke3_digits};

use crate::signatures::winternitz::PublicKey;

use crate::hash::blake3::blake3_var_length;

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
            {71} OP_ROLL
        }
        { U254::from_bytes() } // for y
        { Fq::toaltstack() } // push y to alt stack
        { U254::from_bytes() } // for x
        { Fq::fromaltstack() } // pop y from alt stack, now we have G1Affine form of P on the stack
        { G1Affine::into_projective() } // convert G1Affine P to G1Projective P
        { G1Projective::toaltstack() } // push P back to alt stack
        
        // generate e = h(Rx || M)
        for _ in (0..36) {// copy Rx to the top of ths stack giving ud Rx || tx on the stack
            {255} OP_ROLL
        }
        { blake3_var_length(220) } // hash (Rx || tx-without the singature attributes)
        { reorder_blake3_output_for_le_bytes() }
        { Fr::from_hash() }

        // now e is at the top if the stack
        { G1Projective::toaltstack() } // pop G1Projective P to the top of the stack
        { Fr::copy(3) } // bring e to the top of the stack, and P right under it
        { G1Projective::scalar_mul() } // egenerate eP = e * P
        { G1Projective::toaltstack() } // push eP to alt stack

    }
}