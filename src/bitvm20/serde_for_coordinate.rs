use num_bigint::BigUint;

pub fn serialize_bn254_element(s : &BigUint) -> [u8; 36] {
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

pub fn deserialize_bn254_element(d : &[u8]) -> BigUint {
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
    return result;
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
        p = serialize_bn254_element(&x1);
        println!("p = {:0x?}", p);
        let x2 = deserialize_bn254_element(&p);
        assert!((x1 == x2), "test failed, x1 != x2, bug in serializer or deserializer");
        println!("x1 == x2 -> {}", (x1 == x2));
    }
}