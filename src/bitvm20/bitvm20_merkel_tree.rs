use crate::bitvm20::bitvm20_entry::{bitvm20_entry,bitvm20_entry_serialized_size,default_bitvm20_entry};

pub const levels : usize = 5; // number of elements in the merkel tree is 2^levels -> height being (levels+1)
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

    // genertae just the root of the merkel tree
    pub fn generate_root(&self) -> [u8; 32] {
        let mut curr_level_hashes : Vec<[u8; 32]> = vec![];
        for i in (0..bitvm20_merkel_tree_size) {
            curr_level_hashes.push(self.entries[i].hash());
        }
        
        while curr_level_hashes.len() > 1 {
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
        }

        return curr_level_hashes[0];
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
            result.root_n_siblings[curr_level] = curr_level_hashes[index ^ 0x01];

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

    /* TODO
    fn apply_transaction(&self, tx : &bitvm20_transaction) -> bool {

    }*/

    /* TODO
    fn undo_transaction(&self, tx : &bitvm20_transaction) -> bool {

    }*/
}

impl bitvm20_merkel_proof {
    // validate merke proof
    pub fn validate_proof(&self) -> bool {
        // index out of bounds
        if self.entry_index >= bitvm20_merkel_tree_size {
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
                if index % 2 == 1 { // for odd index
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

    pub fn serialize_for_script2_3(&self) -> Vec<u8> {
        let mut result : Vec<u8> = vec![];
        let mut index = self.entry_index;
        for i in (0..levels).rev() {
            result.push(((index >> i) & 0x01) as u8)
        }
        for x in &self.serialized_entry {
            result.push(*x);
        }
        for x in self.root_n_siblings.iter().rev() {
            for y in x {
                result.push(*y);
            }
        }
        return result;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_bigint::{BigUint};

    #[test]
    fn test_bitvm20_merkel_tree_proofs() {
        #[rustfmt::skip]

        let mut mt = bitvm20_merkel_tree::New();
        
        for i in 0..32 {
            mt.assign(bitvm20_entry{
                public_key: [((i+24) & 0xff) as u8; 64],
                nonce: ((i + 400) * 13) as u64,
                balance: BigUint::from_bytes_be(&[(((i + 13) * 13) & 0xff) as u8; 10]),
            });
        }

        let root = mt.generate_root();
        println!("actual root = {:0x?}", root);
        
        for i in 0..32 {
            let p = mt.generate_proof(i);
            assert!(!p.is_none(), "Generated none proof");
            let pr = p.unwrap();
            println!("proof root = {:0x?}", pr.root_n_siblings[0]);
            assert!(root == pr.root_n_siblings[0], "roots dont match");
            let vl = pr.validate_proof();
            println!("validity of {}-th proof = {}", i, vl);
            assert!(vl, "proof invalid for merkel tree");
            println!("proof for index {} validated !!!", i)
        }
    }
}