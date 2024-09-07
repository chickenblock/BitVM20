use std::cell::RefCell;
use std::rc::Rc;

use crate::bridge::contexts::verifier;
use crate::treepp::{script, Script};
use chrono::Utc;
use num_bigint::BigUint;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use crate::signatures::winternitz::{PublicKey, ZeroPublicKey};
use super::bitvm20_brodacast_packet::bitvm20_broadcast_packet;
use super::bitvm20_challengable_transaction::bitvm20_challengable_transaction;
use super::bitvm20_execution_context::bitvm20_execution_context;
use super::bitvm20_merkel_tree::{bitvm20_merkel_proof, bitvm20_merkel_tree};
use super::bitvm20_transaction::{bitvm20_transaction};
use super::bitvm20_entry::{bitvm20_entry};
use super::bitvm20_user_transaction::bitvm20_user_transaction;
use super::bitvm20_verifier::bitvm20_verifier;
use num_traits::Zero;

pub struct bitvm20_operator {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_challengable_transaction>, // all transactions applied so far

    pub verifiers : Vec<Rc<RefCell<bitvm20_verifier>>>,
}

impl bitvm20_operator {
    // take database file as input
    pub fn new(verifiers : &Vec<Rc<RefCell<bitvm20_verifier>>>) -> bitvm20_operator {
        return bitvm20_operator {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],

            verifiers : verifiers.clone(),
        };
    }

    // TODO
    pub fn assign_user(user : &bitvm20_entry) -> Option<usize> {
        return None;
    }

    // called by the user to generate the transaction object and the broadcast
    pub fn post_transaction_and_receive_broadcast(&mut self, utx : &bitvm20_user_transaction) -> Option<bitvm20_broadcast_packet> {
        
        // generate bitvm20_transaction from user_transaction
        let tx = match self.state_tree.generate_transaction_from_user_transaction(utx) {
            None => {return None;},
            Some(tx) => {tx}
        };

        // primary validate transaction
        if(!self.state_tree.primary_validate_transaction(&tx)) {
            return None;
        }
        // generate merkel proofs, merkel proofs must exist, if a bitvm20_transaction can be created from the user_transaction
        let from_entry_merkel_proof = self.state_tree.generate_proof(utx.from_user_id).unwrap();
        let to_entry_merkel_proof = self.state_tree.generate_proof(utx.to_user_id).unwrap();
        // verify transaction signature
        if(!tx.verify_signature()) {
            return None;
        }

        // if the above validations pass then the transation can be applied to the current state


        // generate random vector of strings for winternitz private keys
        let mut prng = ChaCha20Rng::seed_from_u64(Utc::now().timestamp() as u64);
        let mut winternitz_private_keys : Vec<String> = vec![];
        for _ in 0..1022 {
            let mut wpk = String::from("");
            for _ in 0..40 {
                wpk.push(char::from_digit(prng.next_u32() % 36, 36).unwrap());
            }
            winternitz_private_keys.push(wpk);
        }
        // generate all execution contexts
        let mut exec_contexts : Vec<bitvm20_execution_context> = vec![];
        {
            // script 1
            exec_contexts.extend(self.state_tree.generate_execution_contexts_for_merkel_root_validation(&winternitz_private_keys[0..1], &[ZeroPublicKey; 0], &[script!{}; 0]));
            
            // script 2
            let (v, r) = from_entry_merkel_proof.generate_execution_contexts_for_merkel_proof_validation(&winternitz_private_keys[1..2], &[ZeroPublicKey; 0], &[script!{}; 0]);
            assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);
            
            // script 3
            let (v, r) = to_entry_merkel_proof.generate_execution_contexts_for_merkel_proof_validation(&winternitz_private_keys[2..3], &[ZeroPublicKey; 0], &[script!{}; 0]);
            assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);

            // script 4
            let (v, r) = self.state_tree.generate_execution_contexts_for_primary_validation_of_transaction(&tx, &winternitz_private_keys[3..4], &[ZeroPublicKey; 0], &[script!{}; 0]);
            assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);

            // script 5
            let (v, r) = tx.generate_execution_contexts_for_signature_verification(&winternitz_private_keys[4..1022], &[ZeroPublicKey; 0], &[script!{}; 0]);
            assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);
        }

        // generate broadcast_packet out of bitvm20_transaction and the execution contexts
        let broadcast_packet = bitvm20_broadcast_packet::new(&tx, &exec_contexts);

        // generate locking transaction and send it to bitcoin
        // TODO

        // now broadcast this packet to all verifiers
        let mut verifier_signatures = vec![];
        for v in self.verifiers.iter() {
            match v.borrow_mut().receive_broadcast(&broadcast_packet) {
                None => {return None;},
                Some(verifier_signature) => {verifier_signatures.push(verifier_signature)},
            }
        }

        // note down verifier signatures for the transaction on hold
        // and then move the transaction on hold to applied transactions
        self.tx_history.push(bitvm20_challengable_transaction::new(&tx, &verifier_signatures));

        // apply the transaction on hold
        self.state_tree.apply_transaction(&tx);

        // return the broadcast packed so that everyone in the world can challenge
        return Some(broadcast_packet);
    }
}