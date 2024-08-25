use num_bigint::BigUint;
use num_traits::Num;
use std::ops::{Add, Mul, Rem, Shl, BitAnd};

// input has to be atleast 32 bytes slice, in little endian bytes
pub fn from_hash(hash : &[u8]) -> BigUint {
    let N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();
    //let R = BigUint::from_str_radix("dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57", 16).unwrap();
    //let Rinv = BigUint::from_str_radix("1be7cbeb2ac214c05dee57a5ce4e849f4ee5aa561380deb5f511f723626d88cb", 16).unwrap();

    let hash_value = BigUint::from_bytes_le(hash).rem(BigUint::ZERO.add(1u32).shl(256u32));

    // most significant 3 bits
    let msb_3 = hash_value.clone().bitand(BigUint::from(7u32).shl(253));

    let mut result : BigUint = hash_value.add(&msb_3);
    result = result.rem(N);

    return result;
}