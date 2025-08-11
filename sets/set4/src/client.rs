/// Client for set 4
//
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                        Version 3, 19 November 2007
//
//     Copyright (C) 2024 Debajyoti Debnath
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published
//     by the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
//
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
use set4::*;

#[tokio::main]
async fn main() {
    let filename = "foo".to_string();
    let guessed_signature =
        hmac_sha1_timing_attack(&filename, &"localhost".to_string(), 3000u16).await;
    println!("Guess : {}", &guessed_signature);
    println!(
        "Actual: {}",
        &hmac_sha1(&filename.as_bytes().to_vec(), &b"key".to_vec())
    );
}
