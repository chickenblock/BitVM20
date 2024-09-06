use ark_bn254::{Fr, G1Affine};
use ark_ec::AffineRepr;
use num_bigint::BigUint;
use super::{bitvm20_entry::bitvm20_entry, bitvm20_transaction::bitvm20_transaction};
use num_traits::Zero;


pub struct bitvm20_user_transaction {
    pub from_user_id : usize,
    pub to_user_id : usize,
    pub value : BigUint,

    pub r : G1Affine,
    pub s : Fr,
}

impl bitvm20_user_transaction {
    pub fn new(from_private_key : &Fr, from_user_id : usize, from_user_entry : &bitvm20_entry, to_user_id : usize, to_user_entry : &bitvm20_entry, value : &BigUint) -> bitvm20_user_transaction {
        // generate bitvm20_transaction
        let mut tx = bitvm20_transaction::new_unsigned(from_user_entry, to_user_entry, value);
        tx.sign_transaction(from_private_key);
        
        return bitvm20_user_transaction {
            from_user_id : from_user_id,
            to_user_id : to_user_id,
            value : value.clone(),
            r : tx.r.clone(),
            s : tx.s.clone(),
        };
    }
}