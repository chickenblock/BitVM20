use std::collections::HashMap;
use std::ops::{Add, Shl, Sub};

use crate::treepp::{Script};
use crate::bitvm20::bitvm20_entry::{bitvm20_entry,default_bitvm20_entry};
use crate::bitvm20::bitvm20_execution_context::{bitvm20_execution_context,simple_script_generator};
use crate::bitvm20::bitvm20_transaction::{bitvm20_transaction};
use crate::signatures::winternitz::PublicKey;
use ark_bn254::{G1Affine, G1Projective, Fq, Fr};
use ark_ff::Zero;
use num_bigint::BigUint;
use crate::bitvm20::serde_for_uint::{serialize_256bit_biguint,serialize_u64,deserialize_256bit_biguint,deserialize_u64};
use std::ops::{Add, Sub};
use super::bitvm20_execution_context::script1_generator;
use super::bitvm20_user_transaction::bitvm20_user_transaction;
use super::script1::construct_script1;
use super::script2_3::construct_script2_3;
use super::script4::construct_script4;

pub const levels : usize = 5; // number of elements in the merkel tree is 2^levels -> height being (levels+1)
pub const bitvm20_merkel_tree_size : usize = (1<<levels);

pub struct bitvm20_merkel_tree {
    entries_assigned: usize, // can be atmost (1<<levels)
    entries : [bitvm20_entry; bitvm20_merkel_tree_size], // it can hold atmost (1 << levels) 
    entries_index : HashMap<G1Affine, usize>, // index to get index of the used entry from the user's public key
}

pub struct bitvm20_merkel_proof {
    root_n_siblings : [[u8; 32]; (levels + 1)], // root is at index 0, rest all are siblings to the entry or its parents
    entry : bitvm20_entry,
    entry_index: usize,
}

impl bitvm20_merkel_tree {

    pub fn new() -> bitvm20_merkel_tree {
        return bitvm20_merkel_tree {
            entries_assigned: 0,
            entries: [default_bitvm20_entry; bitvm20_merkel_tree_size],
            entries_index: HashMap::new(),
        }
    }

    pub fn assign(&mut self, ent: bitvm20_entry) -> Option<usize> {
        if self.entries_assigned == bitvm20_merkel_tree_size {
            return None;
        }
        self.entries[self.entries_assigned] = ent;
        self.entries_index.insert(self.entries[self.entries_assigned].public_key.clone(), self.entries_assigned);
        self.entries_assigned+=1;
        return Some(self.entries_assigned-1);
    }

    pub fn get_entry_by_index(&self, index: usize) -> Option<&bitvm20_entry> {
        if index >= self.entries_assigned {
            return None;
        }
        return Some(&(self.entries[index]));
    }

    pub fn get_index_by_public_key(&self, public_key: &G1Affine) -> Option<&usize> {
        return self.entries_index.get(public_key);
    }

    pub fn get_entry_by_public_key(&self, public_key: &G1Affine) -> Option<&bitvm20_entry> {
        let index_opt = self.entries_index.get(public_key);
        match index_opt {
            None => {
                return None;
            }
            Some(index) => {
                return self.get_entry_by_index(*index);
            }
        }
    }

    fn update_bitvm20_entry(&mut self, new_entry: &bitvm20_entry) -> bool {
        return match self.entries_index.get(&new_entry.public_key) {
            None => false,
            Some(index) => {
                self.entries[*index] = new_entry.clone();
                return true;
            }
        }
    }

    // generate just the root of the merkel tree
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
            entry: self.entries[index].clone(),
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

    pub fn generate_transaction(&self, from : usize, to : usize, value : &BigUint) -> Option<bitvm20_transaction> {
        match self.get_entry_by_index(from) {
            None => { return None; },
            Some(from) => {
                match self.get_entry_by_index(to) {
                    None => { return None; }
                    Some(to) => {
                        return Some(bitvm20_transaction::new_unsigned(from, to, value));
                    }
                }
            }
        }
    }

    pub fn generate_transaction_from_user_transaction(&self, utx : &bitvm20_user_transaction) -> Option<bitvm20_transaction> {
        match self.get_entry_by_index(utx.from_user_id) {
            None => { return None; },
            Some(from) => {
                match self.get_entry_by_index(utx.to_user_id) {
                    None => { return None; }
                    Some(to) => {
                        return Some(bitvm20_transaction::new(from, to, &utx.value, &utx.r, &utx.s));
                    }
                }
            }
        }
    }

    pub fn primary_validate_transaction(&self, tx : &bitvm20_transaction) -> bool {
        let from_entry = match self.get_entry_by_public_key(&tx.from_public_key) {
            None => { return false; },
            Some(from_entry) => from_entry
        };

        let to_entry = match self.get_entry_by_public_key(&tx.to_public_key) {
            None => { return false; },
            Some(to_entry) => to_entry
        };

        // nonce does not match
        if tx.from_nonce != from_entry.nonce {
            return false;
        }

        // nonce will overflow
        if tx.from_nonce == u64::MAX {
            return false;
        }

        // from user does not have enough balance
        if from_entry.balance.lt(&tx.value) {
            return false;
        }

        // balnce of the to use may not overflow
        if BigUint::zero().add(1u32).shl(256u32).le(&(to_entry.balance.clone().add(&tx.value))) {
            return false;
        }

        return true;
    }

    pub fn generate_execution_contexts_for_primary_validation_of_transaction(&self, tx : &bitvm20_transaction, winternitz_private_keys : &[String], winternitz_public_keys : &[PublicKey], winternitz_signatures : &[Script]) -> (bool, Vec<bitvm20_execution_context>) {
        let from_entry = match self.get_entry_by_public_key(&tx.from_public_key) {
            None => { return (false, vec![]); },
            Some(from_entry) => from_entry
        };

        let to_entry = match self.get_entry_by_public_key(&tx.to_public_key) {
            None => { return (false, vec![]); },
            Some(to_entry) => to_entry
        };

        let mut result = vec![];

        let mut input : Vec<u8> = vec![];
        input.extend_from_slice(&serialize_256bit_biguint(&tx.value));
        input.extend_from_slice(&serialize_256bit_biguint(&to_entry.balance));
        input.extend_from_slice(&serialize_256bit_biguint(&from_entry.balance));
        input.extend_from_slice(&serialize_u64(from_entry.nonce));
        if(winternitz_private_keys.len() > 0) {
            result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script4))));
        } else {
            result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script4))));
        }

        return (self.primary_validate_transaction(tx), result);
    }

    // the transaction must be validated fully before calling this transaction
    pub fn apply_transaction(&mut self, tx : &bitvm20_transaction) -> bool {
        // primary validation passes, hence the transaction can be applied
        if !self.primary_validate_transaction(&tx) {
            return false;
        }

        let mut from_entry = match self.get_entry_by_public_key(&tx.from_public_key) {
            None => { return false; },
            Some(from_entry) => from_entry.clone()
        };

        let mut to_entry = match self.get_entry_by_public_key(&tx.to_public_key) {
            None => { return false; },
            Some(to_entry) => to_entry.clone()
        };

        // update local copies
        from_entry.balance = from_entry.balance.sub(&tx.value);
        to_entry.balance = to_entry.balance.add(&tx.value);
        from_entry.nonce += 1;

        // update from and to entries
        self.update_bitvm20_entry(&from_entry);
        self.update_bitvm20_entry(&to_entry);
        return true;
    }

    // use this function only on the latest applied transaction on the merkle tree
    pub fn undo_transaction(&mut self, tx : &bitvm20_transaction) -> bool {
        let mut from_entry = match self.get_entry_by_public_key(&tx.from_public_key) {
            None => { return false; },
            Some(from_entry) => from_entry.clone()
        };

        let mut to_entry = match self.get_entry_by_public_key(&tx.to_public_key) {
            None => { return false; },
            Some(to_entry) => to_entry.clone()
        };

        // minor check, rememeber we do not validate anything there, hence use this function only on the most recently applied transaction
        if(from_entry.nonce == 0) {
            return false;
        }

        // update local copies
        from_entry.balance = from_entry.balance.add(&tx.value);
        to_entry.balance = to_entry.balance.sub(&tx.value);
        from_entry.nonce -= 1;

        // update from and to entries
        self.update_bitvm20_entry(&from_entry);
        self.update_bitvm20_entry(&to_entry);
        return true;
    }

    pub fn generate_execution_contexts_for_merkel_root_validation(&self, winternitz_private_keys : &[String], winternitz_public_keys : &[PublicKey], winternitz_signatures : &[Script]) -> Vec<bitvm20_execution_context> {
        let mut result = vec![];

        let mut input : Vec<u8> = vec![];
        input.extend_from_slice(&self.generate_root());
        if(winternitz_private_keys.len() > 0) {
            result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(script1_generator::new(construct_script1, &input))));
        } else {
            result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(script1_generator::new(construct_script1, &input))));
        }

        return result;
    }
}

impl bitvm20_merkel_proof {
    // validate merke proof
    pub fn validate_proof(&self) -> bool {
        // index out of bounds
        if self.entry_index >= bitvm20_merkel_tree_size {
            return false;
        }

        let mut index = self.entry_index;

        let mut curr_hash = self.entry.hash();

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

    pub fn generate_execution_contexts_for_merkel_proof_validation(&self, winternitz_private_keys : &[String], winternitz_public_keys : &[PublicKey], winternitz_signatures : &[Script]) -> (bool, Vec<bitvm20_execution_context>) {
        let mut result = vec![];

        {
            let mut input : Vec<u8> = vec![];
            let mut index = self.entry_index;
            for i in (0..levels).rev() {
                input.push(((index >> i) & 0x01) as u8)
            }
            input.extend_from_slice(&self.entry.serialize());
            for x in self.root_n_siblings.iter().rev() {
                input.extend_from_slice(x);
            }
            if(winternitz_private_keys.len() > 0) {
                result.push(bitvm20_execution_context::new(&winternitz_private_keys[result.len()], &input, Box::new(simple_script_generator::new(construct_script2_3))));
            } else {
                result.push(bitvm20_execution_context::new2(&winternitz_public_keys[result.len()], &input, &winternitz_signatures[result.len()], Box::new(simple_script_generator::new(construct_script2_3))));
            }
        }

        return (self.validate_proof(), result);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use num_bigint::{BigUint};
    use ark_ff::BigInt;

    #[test]
    fn test_bitvm20_merkel_tree_proofs() {
        #[rustfmt::skip]

        let mut mt = bitvm20_merkel_tree::new();
        
        for i in 0..32 {
            mt.assign(bitvm20_entry{
                public_key: G1Affine::new_unchecked(Fq::new(BigInt::new([(i+25) as u64; 4])), Fq::new(BigInt::new([(i+26) as u64; 4]))),
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