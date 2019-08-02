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

pub mod account;
pub mod group_session;
pub mod pickling;
pub mod session;

use olm_rs::{account::OlmAccount, utility::OlmUtility, OlmVersion};

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
fn operational_rng() {
    // Check that generated keys aren't the same
    let olm_account = OlmAccount::new();
    let olm_account2 = OlmAccount::new();
    let identity_keys = olm_account.identity_keys();
    let identity_keys2 = olm_account2.identity_keys();
    assert_ne!(identity_keys, identity_keys2);
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
