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
use num_traits::Zero;

pub struct bitvm20_operator {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_challengable_transaction>, // all transactions applied so far

    pub tx_on_hold : Option<bitvm20_transaction>, // a transaction for which verification signatures have not been received
}

impl bitvm20_operator {
    // take database file as input
    pub fn new() -> bitvm20_operator {
        return bitvm20_operator {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],

            tx_on_hold: None,
        };
    }

    // TODO
    pub fn assign_user(user : &bitvm20_entry) -> Option<usize> {
        return None;
    }

    // TODO
    // called by the user to generate the transaction object and the broadcast
    pub fn post_transaction_and_receive_broadcast(&mut self, utx : &bitvm20_user_transaction) -> Option<bitvm20_broadcast_packet> {
        // fail if there is a transaction already on hold
        if !self.tx_on_hold.is_none() {
            return None;
        }
        
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
            let (v, r) = tx.generate_execution_contexts_for_signature_verification(&winternitz_private_keys[3..4], &[ZeroPublicKey; 0], &[script!{}; 0]);
            assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);
        }

        // put the transaction on hold
        self.tx_on_hold = Some(tx.clone());

        // generate broadcast_packet out of bitvm20_transaction and the execution contexts and return it
        return Some(bitvm20_broadcast_packet::new(&tx, &exec_contexts));
    }

    // called after the operator received all the necessary signatures
    pub fn receive_verifier_signatures(&mut self, verifier_signatures : &Vec<String>) -> bool {
        let tx_on_hold = match &self.tx_on_hold { // if there is no transaction on hold then fail
            None => { return false; },
            Some(tx) => {
                tx
            }
        };

        // note down verifier signatures for the transaction on hold
        // and then move the transaction on hold to applied transactions
        self.tx_history.push(bitvm20_challengable_transaction::new(tx_on_hold, verifier_signatures));

        // apply the transaction on hold
        self.state_tree.apply_transaction(tx_on_hold);

        // clear its onhold status
        self.tx_on_hold = None;

        return true;
    }
}