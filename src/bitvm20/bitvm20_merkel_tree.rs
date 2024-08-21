use crate::bitvm20::bitvm20_entry::{bitvm20_entry,bitvm20_entry_serialized_size,default_bitvm20_entry};

pub const levels : usize = 12; // number of elements in the merkel tree is 2^levels -> height being (levels+1)
pub const bitvm20_merkel_tree_size : usize = (1<<levels);

pub struct bitvm20_merkel_tree {
    entries_assigned: usize, // can be atmost (1<<levels)
    entries : [bitvm20_entry; bitvm20_merkel_tree_size], // it can hold atmost (1 << levels) 
    //index : HashMap<Vec<u8>, usize>, // index to get index of the used entry from the user's public key
}

pub struct bitvm20_merkel_proof {
    root_n_siblings : [[u8; 32]; (levels + 1)], // root is at index 0, rest all are siblings to the entry or its parents
    serialized_entry : [u8; bitvm20_entry_serialized_size], // serialized entry size
    entry_index: usize,
}

impl bitvm20_merkel_tree {

    // TODO
    pub fn New() -> bitvm20_merkel_tree {
        return bitvm20_merkel_tree {
            entries_assigned: 0,
            entries: [default_bitvm20_entry; bitvm20_merkel_tree_size],
        }
    }

    // TODO add the entry to index aswell
    pub fn assign(&mut self, ent: bitvm20_entry) -> Option<usize> {
        if self.entries_assigned == bitvm20_merkel_tree_size {
            return None;
        }
        self.entries[self.entries_assigned] = ent;
        self.entries_assigned+=1;
        return Some(self.entries_assigned-1);
    }

    pub fn get_entry_by_index(&self, index: usize) -> Option<&bitvm20_entry> {
        if index >= self.entries_assigned {
            return None;
        }
        return Some(&(self.entries[index]));
    }

    // TODO
    pub fn get_entry_by_public_key(&self, public_key: &[u8; 64]) -> Option<&bitvm20_entry> {
        return None;
    }

    // generate merkel proof for a given index
    pub fn generate_proof(&self, mut index: usize) -> Option<bitvm20_merkel_proof> {
        if index >= bitvm20_merkel_tree_size {
            return None;
        }

        let mut result : bitvm20_merkel_proof = bitvm20_merkel_proof {
            root_n_siblings: [[0; 32]; (levels+1)],
            serialized_entry: self.entries[index].to_bytes(),
            entry_index: index,
        };

        let mut curr_level_hashes : Vec<[u8; 32]> = vec![];
        for i in (0..bitvm20_merkel_tree_size) {
            curr_level_hashes.push(self.entries[i].hash());
        }
        let mut curr_level = levels;
        
        while curr_level_hashes.len() > 1 {
            // insert sibling
            result.root_n_siblings[curr_level] = curr_level_hashes[index & 0x01];

            // prepare hashes for next level
            let mut x : usize = 0;
            while x < curr_level_hashes.len() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&curr_level_hashes[x]);
                hasher.update(&curr_level_hashes[x+1]);
                let data_hash = hasher.finalize();
                curr_level_hashes[x/2] = (*data_hash.as_bytes());
                x += 2;
            }
            curr_level_hashes.resize(curr_level_hashes.len()/2, [0; 32]);
            index/=2;
            curr_level-=1;
        }
        // insert root
        result.root_n_siblings[0] = curr_level_hashes[0];

        return Some(result);
    }

    /*fn apply_transaction(&self, tx : &bitvm20_transaction) -> bool {

    }*/
}

impl bitvm20_merkel_proof {
    // validate merke proof
    pub fn validate_proof(&self) -> bool {
        // index out of bounds
        if(self.entry_index >= bitvm20_merkel_tree_size) {
            return false;
        }

        let mut index = self.entry_index;

        let mut curr_hash : [u8; 32] = [0; 32];
        {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&self.serialized_entry);
            let data_hash = hasher.finalize();
            curr_hash = (*data_hash.as_bytes());
        }

        let mut curr_level = levels;
        while curr_level > 0 {
            {
                let mut hasher = blake3::Hasher::new();
                if(index % 2 == 1) { // for odd index
                    hasher.update(&self.root_n_siblings[curr_level]);
                    hasher.update(&curr_hash);
                } else {
                    hasher.update(&curr_hash);
                    hasher.update(&self.root_n_siblings[curr_level]);
                }
                let data_hash = hasher.finalize();
                curr_hash = (*data_hash.as_bytes());
            }
            curr_level-=1;
            index/=2;
        }

        // if the roots are equal
        return curr_hash == self.root_n_siblings[0];
    }
}