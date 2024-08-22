use num_bigint::{BigUint};
use ark_bn254::{G1Affine, G1Projective};

pub const bitvm20_entry_serialized_size : usize = (32 + 32 + 8 + 32);

pub struct bitvm20_entry {
    pub public_key : [u8; 64], // x, y of the public key
    pub nonce : u64, // 64 bit nonce to be serialized in little endian format
    pub balance : BigUint, // 256 bit unsigned integer to be serialized in little endian format
}

pub const default_bitvm20_entry : bitvm20_entry = bitvm20_entry {
    public_key: [0; 64],
    nonce: 0,
    balance: BigUint::ZERO,
};

impl bitvm20_entry {

    // serialized form of the bitvm20_entry
    pub fn to_bytes(&self) -> [u8; bitvm20_entry_serialized_size] {
        let mut result : [u8; bitvm20_entry_serialized_size] = [0; bitvm20_entry_serialized_size];
        let mut i : usize = 0;
        while i < 32 {
            result[i] = self.public_key[i]; i+=1;
        }
        while i < 64 {
            result[i] = self.public_key[i]; i+=1;
        }
        while i < (64+8) {
            result[i] = ((self.nonce >> (i-64)) & 0xff) as u8; i+=1;
        }
        let temp = self.balance.to_bytes_le();
        while i < (64+8+32) && (i-64-8) < temp.len() {
            result[i] = temp[i-64-8]; i+=1;
        }
        return result;
    }

    // blake3 hash of the serialized bitvm20_entry
    pub fn hash(&self) -> [u8; 32] {
        let serialized = self.to_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serialized);
        let data_hash = hasher.finalize();
        return *data_hash.as_bytes();
    }
}

impl Clone for bitvm20_entry {
    fn clone(&self) -> bitvm20_entry {
        return bitvm20_entry{
            public_key: self.public_key.clone(),
            nonce: self.nonce,
            balance: self.balance.clone(),
        }
    }
}