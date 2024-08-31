/// sha1hash library helpers
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

pub fn u32_rotate_left(num: &u32, mut places: usize) -> u32 {
    places &= 32 - 1;
    if places == 0 {
        return num.clone();
    }
    return (num << places) | (num >> (32 - places));
}

pub fn u32_rotate_right(num: &u32, mut places: usize) -> u32 {
    places &= 32 - 1;
    if places == 0 {
        return num.clone();
    }
    return (num >> places) | (num << (32 - places));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_rotate_left() {
        let num: u32 = 1;
        assert_eq!(u32_rotate_left(&num, 1), (1 << 1) as u32);
    }

    #[test]
    fn test_u32_rotate_right() {
        let num: u32 = 1;
        assert_eq!(u32_rotate_right(&num, 1), (1 << 31) as u32);
    }
}
