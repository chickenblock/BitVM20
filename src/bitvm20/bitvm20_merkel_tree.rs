use crate::bitvm20::bitvm20_entry::{bitvm20_entry,bitvm20_entry_serialized_size,default_bitvm20_entry};

pub const levels : usize = 12; // number of elements in the merkel tree is 2^levels -> height being (levels+1)
pub const bitvm20_merkel_tree_size : usize = (1<<levels);

pub struct bitvm20_merkel_tree {
    //entries_assigned: usize, // can be atmost (1<<levels)
    entries : [bitvm20_entry; bitvm20_merkel_tree_size], // it can hold atmost (1 << levels) 
    //index : HashMap<Vec<u8>, usize>, // index to get index of the used entry from the user's public key
}

pub struct bitvm20_merkel_proof {
    root_n_siblings : [[u8; 32]; (levels + 1)], // root is at index 0, rest all are siblings to the entry or its parents
    serialized_entry : [u8; bitvm20_entry_serialized_size], // serialized entry size
}

impl bitvm20_merkel_tree {

    // TODO
    fn New() -> bitvm20_merkel_tree {
        return bitvm20_merkel_tree {
            entries: [default_bitvm20_entry; bitvm20_merkel_tree_size],
        }
    }

    // TODO
    fn assign(&mut self, ent: bitvm20_entry) -> i64 {
        return -1;
    }

    fn get_entry_by_index(&self, index: usize) -> Option<&bitvm20_entry> {
        if index >= bitvm20_merkel_tree_size {
            return None;
        }
        return Some(&(self.entries[index]));
    }

    // TODO
    fn generate_proof(&self) -> bitvm20_merkel_proof {
        let result : bitvm20_merkel_proof = bitvm20_merkel_proof {
            root_n_siblings: [[0; 32]; (levels+1)],
            serialized_entry: [0; bitvm20_entry_serialized_size],
        };
        return result;
    }

    /*fn apply_transaction(&self, tx : &bitvm20_transaction) -> bool {

    }*/
}