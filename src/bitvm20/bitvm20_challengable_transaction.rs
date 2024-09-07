use super::bitvm20_transaction::bitvm20_transaction;


pub struct bitvm20_challengable_transaction {
    pub tx : bitvm20_transaction,
    pub verifier_signatures : Vec<String>,
}

impl bitvm20_challengable_transaction {
    pub fn new(tx : &bitvm20_transaction, verifier_signatures : &Vec<String>) -> bitvm20_challengable_transaction {
        return bitvm20_challengable_transaction {
            tx : tx.clone(),
            verifier_signatures : verifier_signatures.clone(),
        };
    }
}