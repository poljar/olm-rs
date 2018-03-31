// olm-rs is a simple wrapper for libolm in Rust.
// Copyright (C) 2018  Johannes Hayeß
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

extern crate base64;
extern crate json;
extern crate olm_rs;

use olm_rs::account::OlmAccount;

#[test]
fn identity_keys_valid() {
    let mut olm_account = OlmAccount::new();
    // verify length of entire JSON object
    let identity_keys = olm_account.identity_keys();
    assert_eq!(identity_keys.len(), 116);
    let keys_json = json::parse(&identity_keys).unwrap();
    let curve25519 = String::from(keys_json["curve25519"].as_str().unwrap());
    let ed25519 = String::from(keys_json["ed25519"].as_str().unwrap());
    // verify encoded keys length
    assert_eq!(curve25519.len(), 43);
    assert_eq!(ed25519.len(), 43);
    // encoded as valid base64?
    base64::decode(&curve25519).unwrap();
    base64::decode(&ed25519).unwrap();
}

#[test]
fn operational_rng() {
    // Check that generated keys aren't the same
    let mut olm_account = OlmAccount::new();
    let mut olm_account2 = OlmAccount::new();
    let identity_keys = olm_account.identity_keys();
    let identity_keys2 = olm_account2.identity_keys();
    assert_ne!(identity_keys, identity_keys2);
}
