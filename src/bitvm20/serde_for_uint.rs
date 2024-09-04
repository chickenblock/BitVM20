use num_bigint::BigUint;

pub fn serialize_256bit_biguint(v : &BigUint) -> [u8; 32] {
    let mut result : [u8; 32] = [0; 32];
    for (i, b) in v.to_bytes_le().into_iter().enumerate() {
        result[i] = b;
    }
    return result;
}

pub fn deserialize_256bit_biguint(b : &[u8]) -> BigUint {
    return BigUint::from_bytes_le(&b[0..32]);
}

pub fn serialize_u64(v : u64) -> [u8; 8] {
    let mut result : [u8; 8] = [0; 8];
    for i in 0..8 {
        result[i] = (((v >> (i*8))) & 0xffu64) as u8;
    }
    return result;
}

pub fn deserialize_u64(b : &[u8]) -> u64 {
    let mut res : u64 = 0;
    for i in 0..8 {
        res = res | ((b[i] as u64) << (i * 8));
    }
    return res;
}