use num_bigint::BigUint;

use super::bitvm20_brodacast_packet::bitvm20_broadcast_packet;
use super::bitvm20_execution_context::bitvm20_execution_context;
use super::bitvm20_merkel_tree::{bitvm20_merkel_proof, bitvm20_merkel_tree};
use super::bitvm20_transaction::{bitvm20_transaction};
use num_traits::Zero;

pub struct bitvm20_verifier {
    pub bitcoin_private_key : BigUint,

    pub state_tree : bitvm20_merkel_tree,      // current state of the tree
    pub tx_history : Vec<bitvm20_transaction>, // all transactions applied so far
}

impl bitvm20_verifier {
    // take database file as input
    pub fn new() -> bitvm20_verifier {
        return bitvm20_verifier {
            bitcoin_private_key: BigUint::zero(),

            state_tree: bitvm20_merkel_tree::new(),
            tx_history: vec![],
        };
    }

    pub fn receive_broadcast(&mut self, broadcast_packet : &bitvm20_broadcast_packet) -> Option<String> {
        // ensure that that the bitvm20_broadcast packet has enough signatures for a transaction
        if(broadcast_packet.winternitz_public_keys.len() != 1022 || broadcast_packet.winternitz_signatures.len() != 1022) {
            return None;
        }

        // construct the merkel proofs
        // if the merkel proofs were included in the broadcast packet, then we the verifier only need to validate it
        // i.e. check things like merkel proof root is same as current root, and the entry matches either from_entry or to_entry 
        let from_user_id = match self.state_tree.get_index_by_public_key(&broadcast_packet.tx.from_public_key) {
            None => {return None;},
            Some(from_user_id) => { *from_user_id },
        };
        let to_user_id = match self.state_tree.get_index_by_public_key(&broadcast_packet.tx.to_public_key) {
            None => {return None;},
            Some(to_user_id) => { *to_user_id },
        };
        let from_entry_merkel_proof = self.state_tree.generate_proof(from_user_id).unwrap();
        let to_entry_merkel_proof = self.state_tree.generate_proof(to_user_id).unwrap();

        // construct exection contexts out of the input parameters
        // generate all execution contexts
        let mut exec_contexts : Vec<bitvm20_execution_context> = vec![];
        {
            // script 1
            exec_contexts.extend(self.state_tree.generate_execution_contexts_for_merkel_root_validation(&[String::from(""); 0], &broadcast_packet.winternitz_public_keys[0..1], &broadcast_packet.winternitz_signatures[0..1]));
            
            // script 2
            let (v, r) = from_entry_merkel_proof.generate_execution_contexts_for_merkel_proof_validation(&[String::from(""); 0], &broadcast_packet.winternitz_public_keys[1..2], &broadcast_packet.winternitz_signatures[1..2]);
            //assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);
            
            // script 3
            let (v, r) = to_entry_merkel_proof.generate_execution_contexts_for_merkel_proof_validation(&[String::from(""); 0], &broadcast_packet.winternitz_public_keys[2..3], &broadcast_packet.winternitz_signatures[2..3]);
            //assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);

            // script 4
            let (v, r) = self.state_tree.generate_execution_contexts_for_primary_validation_of_transaction(&broadcast_packet.tx, &[String::from(""); 0], &broadcast_packet.winternitz_public_keys[3..4], &broadcast_packet.winternitz_signatures[3..4]);
            assert!(r.len() != 0, "failed to generate primary validation scripts for tx on verifier"); // important check, if you try to generate primary validation scripts for transaction that does not have its from or to entry in state-tree then it will fail, this must not happen
            //assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);

            // script 5
            let (v, r) = broadcast_packet.tx.generate_execution_contexts_for_signature_verification(&[String::from(""); 0], &broadcast_packet.winternitz_public_keys[4..1022], &broadcast_packet.winternitz_signatures[4..1022]);
            //assert!(v, "making execution contexts for invalid transaction");
            exec_contexts.extend(r);
        }

        // validate each of the exection contexts for a valid input_parameters and their winternitz_signatures
        for x in exec_contexts {
            if !x.validate_input_parameters_and_winternitz_signatures() {
                return None;
            }
        }

        // construct a bitcoin transaction out of script1 and the execution contexts

        // construct a bitcoin's take transaction out of the earlier mentioned transaction

        // sign this transaction and reveal it to the operator
        let take_signature = String::from("");

        // apply this transaction to the merkel tree
        self.state_tree.apply_transaction(&broadcast_packet.tx);

        // send signatiure to the caller
        return Some(take_signature);
    }
}