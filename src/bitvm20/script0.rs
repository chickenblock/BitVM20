use crate::treepp::{script, Script};

use crate::pseudo::OP_CHECKSEQUENCEVERIFY;

// inputs must contain sigantures in reverse order of the public_keys
pub fn construct_script0(blocks_until : i32, public_keys: Vec<[u8; 32]>) -> Script {
    script!{
        {blocks_until} OP_CHECKSEQUENCEVERIFY OP_DROP
        OP_0
        for pk in &public_keys {
            {pk.to_vec()} OP_CHECKSIGADD
        }
        {public_keys.len()} OP_EQUAL
    }
}