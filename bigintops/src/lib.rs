/// bigintops library
// 
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                     Version 3, 19 November 2007


//  Copyright (C) 2024 Debajyoti Debnath

//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.

//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.

//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
// 

use num::{bigint::Sign, BigInt, FromPrimitive};

#[derive(Debug)]
pub enum Error {
    ModInvNotFound
}

pub fn bigint(arr: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, arr)
}

pub fn bytearray(int: &BigInt) -> Vec<u8> {
    int.to_bytes_be().1
}

pub fn modinv_bytes(a_bytes_be: &[u8], n_bytes_be: &[u8]) -> Result<BigInt, Error> {
    let a = bigint(a_bytes_be);
    let n = bigint(n_bytes_be);
    let one = BigInt::from_i32(1).unwrap();
    
    let mut t = BigInt::ZERO;
    let mut r = n.clone();
    let mut new_t = one.clone();
    let mut new_r = a.clone();
    let mut quotient: BigInt;
    let mut temp: BigInt;
    
    while new_r != BigInt::ZERO {
        quotient = r.clone() / new_r.clone();
        
        temp = new_t;
        new_t = t.clone() - quotient.clone() * temp.clone();
        t = temp;

        temp = new_r;
        new_r = r.clone() - quotient.clone() * temp.clone();
        r = temp;
    }

    if r > one {
        return Err(Error::ModInvNotFound);
    }
    if t < BigInt::ZERO {
        t += n;
    }
    Ok(t)
}

pub fn modpow_bytes(base_be_bytes: &[u8], exponent_be_bytes: &[u8], modulus_be_bytes: &[u8]) -> Vec<u8> {
    let base_bigint = BigInt::from_bytes_be(Sign::Plus, base_be_bytes);
    let exponent_bigint = BigInt::from_bytes_be(Sign::Plus, exponent_be_bytes);
    let modulus_bigint = BigInt::from_bytes_be(Sign::Plus, modulus_be_bytes);

    let res = base_bigint.modpow(&exponent_bigint, &modulus_bigint);

    res.to_bytes_be().1
}

pub fn egcd(a_bytes_be: &[u8], b_bytes_be: &[u8]) -> (BigInt, BigInt, BigInt) {
    let a = bigint(a_bytes_be);
    let b = bigint(b_bytes_be);
    
    let mut old_r = a.clone();
    let mut r = b.clone();
    let mut old_s = BigInt::from_i32(1i32).unwrap();
    let mut s = BigInt::ZERO;
    let mut quotient: BigInt;
    let mut temp: BigInt;

    while r != BigInt::ZERO {
        quotient = old_r.clone() / r.clone();

        temp = r;
        r = old_r - quotient.clone() * temp.clone();
        old_r = temp;

        temp = s;
        s = old_s - quotient.clone() * temp.clone();
        old_s = temp;
    }

    let bezout_t = if b != BigInt::ZERO {
        (old_r.clone() - old_s.clone() * a.clone()) / b.clone()
    } else {
        BigInt::ZERO
    };
    (old_s, bezout_t, old_r)
}

pub fn cube_root(number_bytes_be: &[u8]) -> Vec<u8> {
    let num = bigint(number_bytes_be);
    let mut start = BigInt::ZERO;
    let mut end = bigint(number_bytes_be);
    let mut mid = BigInt::ZERO;
    let mut prev_diff = BigInt::ZERO;
    let n_iter = 1_000_000;

    for ctr in 0..n_iter {
        mid = (start.clone() + end.clone()) / 2;
        let diff = num.clone() - mid.clone().pow(3u32);

        if diff.clone() - prev_diff.clone() == BigInt::ZERO {
            break;
        }

        prev_diff = diff.clone();
        
        if diff < BigInt::ZERO {
            end = mid.clone();
        } else {
            start = mid.clone();
        }
        if ctr == n_iter - 1 {
            println!("Warning: cube root did not converge in {} iterations.", &n_iter);
        }
    }
    bytearray(&(mid+1))
}

pub fn bigint_div_ceil(numerator: &BigInt, denominator: &BigInt) -> BigInt {
    if numerator % denominator == BigInt::ZERO {
        return numerator / denominator;
    }
    numerator / denominator + 1
}

pub fn bigint_div_floor(numerator: &BigInt, denominator: &BigInt) -> BigInt {
    numerator / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use vecofbits::BitVec;
    use bytearrayconversion::hextobytearray;

    #[test]
    fn test_modpow_bytes() {
        let base = BitVec::new_from_num(32, &0xABCDEF).to_bytearray();
        let exponent = BitVec::new_from_num(32, &0x123456).to_bytearray();
        let modulus = BitVec::new_from_num(32, &0xFEEDBEEF).to_bytearray();
        let expected = hextobytearray(&"81ce3d04".to_string());
        assert_eq!(modpow_bytes(&base[..], &exponent[..], &modulus[..]), expected)
    }

    #[test]
    fn test_egcd() {
        let a = bytearray(&BigInt::from_i32(1914).unwrap());
        let b = bytearray(&BigInt::from_i32(899).unwrap());
        let gcd = BigInt::from_i32(29).unwrap();
        let bezout_a = BigInt::from_i32(8).unwrap();
        let bezout_b = BigInt::new(Sign::Minus, vec![17u32]);
        let (got_bezout_a, got_bezout_b, got_gcd) = egcd(&a, &b);
        assert_eq!(got_bezout_a, bezout_a);
        assert_eq!(got_bezout_b, bezout_b);
        assert_eq!(got_gcd, gcd);
    }

    #[test]
    fn test_modinv_bytes() {
        let a = bytearray(&BigInt::from_i32(87412453).unwrap());
        let b = bytearray(&BigInt::from_i32(85258).unwrap());
        let expected = BigInt::from_i32(35055).unwrap();
        
        assert_eq!(modinv_bytes(&a, &b).unwrap(), expected);
    }
}
