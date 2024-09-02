use ark_ec::AffineRepr;
use bitcoin::psbt::serialize;
use num_bigint::BigUint;
use num_traits::Num;
use std::ops::{Add, Mul, Shl, Rem};

pub fn serialize_bn254_element(_s : &BigUint, is_Fq : bool) -> [u8; 36] {
    let mut N : BigUint = BigUint::ZERO;
    if is_Fq {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
    } else {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();
    }
    let mut R : BigUint = BigUint::ZERO;
    if is_Fq {
        R = BigUint::from_str_radix("dc83629563d44755301fa84819caa36fb90a6020ce148c34e8384eb157ccc21", 16).unwrap();
    } else {
        R = BigUint::from_str_radix("dc83629563d44755301fa84819caa8075bba827a494b01a2fd4e1568fffff57", 16).unwrap();
    }

    let s = _s.mul(&R).rem(&N);

    let mut result : [u8; 36] = [0; 36];
    let mut bits_consumed : usize = 0;
    let mut bytes_produced : usize = 0;
    while(bits_consumed < 254) {
        for _ in 0..3 {
            for i in 0..8 {
                result[bytes_produced] |= ((s.bit(bits_consumed as u64) as u8) << i);
                bits_consumed+=1;
            }
            bytes_produced+=1;
        }
        for i in 0..5 {
            result[bytes_produced] |= ((s.bit(bits_consumed as u64) as u8) << i);
            bits_consumed+=1;
        }
        bytes_produced+=1;
    }
    return result;
}

pub fn deserialize_bn254_element(d : &[u8], is_Fq : bool) -> BigUint {
    let mut N : BigUint = BigUint::ZERO;
    if is_Fq {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();
    } else {
        N = BigUint::from_str_radix("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16).unwrap();
    }
    let mut Rinv : BigUint = BigUint::ZERO;
    if is_Fq {
        Rinv = BigUint::from_str_radix("18223d71645e71455ce0bffc0a6ec602ae5dab0851091e61fb9b65ed0584ee8b", 16).unwrap();
    } else {
        Rinv = BigUint::from_str_radix("1be7cbeb2ac214c05dee57a5ce4e849f4ee5aa561380deb5f511f723626d88cb", 16).unwrap();
    }

    let mut result : BigUint = BigUint::ZERO;
    let mut bytes_consumed : usize = 0;
    let mut bits_produced : usize = 0;
    while(bits_produced < 254) {
        for _ in 0..3 {
            for i in 0..8 {
                result.set_bit(bits_produced as u64, ((d[bytes_consumed] >> i) & 0x01) == 0x01);
                bits_produced+=1;
            }
            bytes_consumed+=1;
        }
        for i in 0..5 {
            result.set_bit(bits_produced as u64, ((d[bytes_consumed] >> i) & 0x01) == 0x01);
            bits_produced+=1;
        }
        bytes_consumed+=1;
    }

    return result.mul(&Rinv).rem(&N);
}

#[cfg(test)]
mod test {
    use super::*;
    use num_bigint::{BigUint};

    #[test]
    fn test_coord_serde() {
        #[rustfmt::skip]

        let x1 = BigUint::parse_bytes(b"1a5aa55ababaef123456789abcdeffedcba987654321f123456789abcdeba987", 16).expect("invalid input for x1");
        let mut p : [u8; 36] = [0; 36];
        p = serialize_bn254_element(&x1, true);
        println!("p = {:0x?}", p);
        let x2 = deserialize_bn254_element(&p, true);
        assert!((x1 == x2), "test failed, x1 != x2, bug in serializer or deserializer");
        println!("x1 == x2 -> {}", (x1 == x2));

        let x1 = BigUint::parse_bytes(b"1a5aa55ababaef123456789abcdeffedcba987654321f123456789abcdeba987", 16).expect("invalid input for x1");
        let mut p : [u8; 36] = [0; 36];
        p = serialize_bn254_element(&x1, false);
        println!("p = {:0x?}", p);
        let x2 = deserialize_bn254_element(&p, false);
        assert!((x1 == x2), "test failed, x1 != x2, bug in serializer or deserializer");
        println!("x1 == x2 -> {}", (x1 == x2));
    }
}