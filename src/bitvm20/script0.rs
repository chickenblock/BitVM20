use bitcoin::PublicKey;

use crate::treepp::{script, Script};

// inputs must contain sigantures in reverse order of the public_keys
pub fn construct_script0(blocks_until : i32, public_keys: &Vec<PublicKey>) -> Script {
    script!{
        {blocks_until} OP_CSV OP_DROP
        OP_0
        for pk in public_keys {
            {*pk} OP_CHECKSIGADD
        }
        {public_keys.len()} OP_EQUAL
    }
}