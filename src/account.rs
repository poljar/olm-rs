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

use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::mem;

/// An olm account manages all cryptographic keys used on a device.
pub struct OlmAccount {
    // Reserved memory buffer holding data of an OlmAccount for libolm
    _olm_account_buf: Vec<u8>,
    // Pointer by which libolm aquires the data saved in an instance of OlmAccount
    olm_account_ptr: *mut olm_sys::OlmAccount,
}

impl OlmAccount {
    /// Creates a new instance of OlmAccount. During the instanciation the Ed25519 fingerprint key pair
    /// and the Curve25519 identity key pair are generated. For more information see:
    /// https://matrix.org/docs/guides/e2e_implementation.html#keys-used-in-end-to-end-encryption
    pub fn new() -> Self {
        let olm_account_ptr;
        let mut olm_account_buf: Vec<u8>;
        unsafe {
            // allocate buffer for OlmAccount to be written into
            olm_account_buf = vec![0; olm_sys::olm_account_size()];
            olm_account_ptr = olm_sys::olm_account(olm_account_buf.as_mut_ptr() as *mut _);

            let mut random_bytes: Vec<u8> = vec![0; 1024]; // length of random_bytes buffer is guessed
            {
                let rng = SystemRandom::new();
                rng.fill(random_bytes.as_mut_slice()).unwrap();
            }

            let random_bytes_ptr = random_bytes.as_mut_ptr() as *mut _;
            // TODO: handle potential errors
            olm_sys::olm_create_account(olm_account_ptr, random_bytes_ptr, 1024);
        }

        OlmAccount {
            _olm_account_buf: olm_account_buf,
            olm_account_ptr: olm_account_ptr,
        }
    }

    /// Returns the account's public identity keys already formatted as JSON and BASE64.
    pub fn identity_keys(&mut self) -> String {
        let identity_keys_result: String;
        unsafe {
            // get buffer size of identity keys
            let keys_size = olm_sys::olm_account_identity_keys_length(self.olm_account_ptr);
            let mut identity_keys_buf: Vec<u8> = vec![0; keys_size];
            let identity_keys_ptr = identity_keys_buf.as_mut_ptr() as *mut _;

            // write keys data in the keys buffer
            // TODO: handle potential errors
            olm_sys::olm_account_identity_keys(self.olm_account_ptr, identity_keys_ptr, keys_size);

            // To avoid a double memory free we have to forget about our buffer,
            // since we are using the buffer's data to construct the final string below.
            mem::forget(identity_keys_buf);

            // String is constructed from the keys buffer and memory is freed after exiting the scope.
            // No memory should be leaked.
            identity_keys_result =
                String::from_raw_parts(identity_keys_ptr as *mut u8, keys_size, keys_size);
        }

        identity_keys_result
    }
}
