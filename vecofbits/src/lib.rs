/// vecofbits library
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

use itertools::{Itertools, EitherOrBoth::*};

#[derive(Debug, PartialEq)]
pub enum BitVecError {
    Overflow(usize)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitVec {
    data: Vec<u8>,
}

impl BitVec {
    pub fn new(size_arg: usize) -> BitVec {
        BitVec{ data: Vec::<u8>::with_capacity(size_arg) }
    }

    pub fn new_from_num(size_arg: usize, num: &u32) -> BitVec {
        if size_arg % 8 > 0 {
            panic!("Bit vector size must be multiple of 8.")
        }
        let mut res = BitVec{ data: vec![0x00u8; size_arg] };
        res.populate(num);
        res
    }

    pub fn new_from_bytearray(bytearr: &Vec<u8>) -> BitVec {
        let mut vec = BitVec::new(bytearr.len()*8);
        let data: Vec<u8> = bytearr
                            .iter()
                            .map(|byte| BitVec::new_from_num(8, &(*byte as u32)).get_data().clone())
                            .flatten()
                            .collect();
        vec.extend(data);
        vec
    }

    pub fn populate(&mut self, num: &u32) {
        self.data = (0..(self.data.len() as u32))
            .rev()
            .map(|ctr| num & (1 << ctr))
            .map(|val| if val > 0 { 0x01 } else { 0x00 })
            .collect();
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn push(&mut self, bit: u8) {
        if bit != 0x01u8 && bit != 0x00u8 {
            panic!("Cannot push non-bit character.");
        }
        self.data.push(bit);
    }

    pub fn extend(&mut self, bitvec: Vec<u8>) {
        for bit in bitvec.iter() {
            if *bit != 0x01u8 && *bit != 0x00u8 {
                panic!("Cannot push non-bit character.")
            }
        }
        self.data.extend(bitvec);
    }

    pub fn to_num(&self) -> Result<u32, BitVecError> {
        if self.data.len() > 32 {
            Err(BitVecError::Overflow(self.data.len()))
        } else {
            Ok(self.data
                .iter()
                .enumerate()
                .map(|(ctr, x)| *x as u32 * ((1 << (self.data.len()-ctr-1)) as u32))
                .sum())
        }
    }

    pub fn to_bytearray(&self) -> Vec<u8> {
        self.data
                .chunks(8)
                .map(|chunk| chunk.iter().enumerate().map(|(ctr, x)| *x as u8 * ((1 << (8-ctr-1)) as u8)).sum())
                .collect()
    }

    pub fn left_shift(&mut self, places: usize) {
        self.data.extend(vec![0x00u8; places])
    }

    pub fn bitwise_or(&self, other: &BitVec) -> BitVec {
        let res: Vec<u8> = self.data.iter().rev().zip_longest(other.get_data().iter().rev())
            .map(|pair| match pair {
                    Both(l, r) => l | r,
                    Left(l) => *l,
                    Right(r) => *r
             })
            .rev()
            .collect();
        let mut res_bitvec = BitVec::new(std::cmp::max(self.len(), other.len()));
        res_bitvec.extend(res);
        res_bitvec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitvec_bytearray_conversion() {
        let bytearr: Vec<u8> = b"Cowabunga".to_vec();
        assert_eq!(BitVec::new_from_bytearray(&bytearr).to_bytearray(), bytearr);
    }

    #[test]
    fn test_bitvec_number_conversion() {
        let number: u32 = 0xFEEDBEEF;
        assert_eq!(BitVec::new_from_num(32, &number).to_num().unwrap(), number);
    }

    #[test]
    fn test_bitvec_left_shift() {
        let mut bitvec = BitVec::new_from_num(8, &0x80);
        bitvec.left_shift(8);
        assert_eq!(bitvec, BitVec::new_from_num(16, &0x8000));
    }

    #[test]
    fn test_bitvec_bitwise_or() {
        let mut bitvec = BitVec::new_from_num(8, &0x80);
        bitvec.left_shift(8);
        assert_eq!(bitvec.bitwise_or(&BitVec::new_from_num(8, &0x80)), BitVec::new_from_num(16, &0x8080));
    }
}
