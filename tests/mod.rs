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
use olm_rs::errors::OlmAccountError;
use olm_rs::utility::OlmUtility;
use olm_rs::*;

#[test]
fn library_version_valid() {
    let invalid_olm_version = OlmVersion {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let olm_version = olm_rs::get_library_version();
    println!(
        "Olm version: {}.{}.{}",
        olm_version.major, olm_version.minor, olm_version.patch
    );
    assert_ne!(olm_version, invalid_olm_version);
}

#[test]
fn identity_keys_valid() {
    let olm_account = OlmAccount::new();
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
    let olm_account = OlmAccount::new();
    let olm_account2 = OlmAccount::new();
    let identity_keys = olm_account.identity_keys();
    let identity_keys2 = olm_account2.identity_keys();
    assert_ne!(identity_keys, identity_keys2);
}

#[test]
fn signatures_valid() {
    // test signature being valid base64
    let olm_account = OlmAccount::new();
    let mut bytes: Vec<u8> = vec![72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33];
    let signature = olm_account.sign_bytes(bytes.as_mut_slice());
    assert_eq!(signature.len(), 86);
    base64::decode(&signature).unwrap();

    // test sign_bytes() and sign_utf8_msg() on identical input
    let mut message = String::from("Hello world!");
    let mut message_same = String::from("Hello world!");
    let message_as_bytes = unsafe { message_same.as_bytes_mut() };
    assert_eq!(
        olm_account.sign_bytes(message_as_bytes),
        olm_account.sign_utf8_msg(message.as_mut_str())
    )
}

#[test]
fn one_time_keys_valid() {
    let mut olm_account = OlmAccount::new();
    let max_number_otks = olm_account.max_number_of_one_time_keys();
    assert_eq!(100, max_number_otks);

    // empty read of one time keys
    let otks_empty = olm_account.one_time_keys();
    let otks_empty_json = json::parse(&otks_empty).unwrap();
    assert!(otks_empty_json["curve25519"].is_object());
    assert!(otks_empty_json["curve25519"].is_empty());

    olm_account.generate_one_time_keys(20);
    let otks_filled = olm_account.one_time_keys();
    let otks_filled_json = json::parse(&otks_filled).unwrap();
    assert_eq!(20, otks_filled_json["curve25519"].len());
    for entry in otks_filled_json["curve25519"].entries() {
        assert_eq!(6, entry.0.len());
        let key = entry.1.as_str().unwrap();
        base64::decode(&key).unwrap();
    }

    olm_account.mark_keys_as_published();

    // empty read of one time keys after marking as published
    let otks_empty = olm_account.one_time_keys();
    let otks_empty_json = json::parse(&otks_empty).unwrap();
    assert!(otks_empty_json["curve25519"].is_object());
    assert!(otks_empty_json["curve25519"].is_empty());
}

#[test]
fn sha256_valid() {
    let mut test_str = String::from("Hello, World!");
    let util = OlmUtility::new();
    let mut test_str_same = String::from("Hello, World!");
    let test_str_bytes = unsafe { test_str_same.as_bytes_mut() };

    assert_eq!(
        util.sha256_utf8_msg(&mut test_str),
        util.sha256_bytes(test_str_bytes)
    )
}

#[test]
fn pickling_fails_on_wrong_key() {
    let mut pickled;
    {
        let mut olm_account = OlmAccount::new();
        pickled = olm_account.pickle(&[3, 2, 1]);
    }
    // wrong key
    let olm_account_bad = OlmAccount::unpickle(&mut pickled, &[1, 2, 3]);

    assert!(olm_account_bad.is_err());
    assert_eq!(olm_account_bad.err(), Some(OlmAccountError::BadAccountKey));
}
