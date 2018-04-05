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
use errors;
use errors::OlmAccountError;
use std::ffi::CStr;

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
        let create_error;
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
            create_error = olm_sys::olm_create_account(olm_account_ptr, random_bytes_ptr, 1024);
        }

        // No instance of OlmAccount exists yet, so we have to assume the error was with the random data
        if create_error == errors::olm_error() {
            panic!("Not enough random data was supplied for creation of OlmAccount!");
        }

        OlmAccount {
            _olm_account_buf: olm_account_buf,
            olm_account_ptr: olm_account_ptr,
        }
    }

    /// Returns the account's public identity keys already formatted as JSON and BASE64.
    pub fn identity_keys(&mut self) -> String {
        let identity_keys_result: String;
        let identity_keys_error;
        unsafe {
            // get buffer size of identity keys
            let keys_size = olm_sys::olm_account_identity_keys_length(self.olm_account_ptr);
            let mut identity_keys_buf: Vec<u8> = vec![0; keys_size];
            let identity_keys_ptr = identity_keys_buf.as_mut_ptr() as *mut _;

            // write keys data in the keys buffer
            identity_keys_error = olm_sys::olm_account_identity_keys(
                self.olm_account_ptr,
                identity_keys_ptr,
                keys_size,
            );

            // To avoid a double memory free we have to forget about our buffer,
            // since we are using the buffer's data to construct the final string below.
            mem::forget(identity_keys_buf);

            // String is constructed from the keys buffer and memory is freed after exiting the scope.
            // No memory should be leaked.
            identity_keys_result =
                String::from_raw_parts(identity_keys_ptr as *mut u8, keys_size, keys_size);
        }

        if identity_keys_error == errors::olm_error() {
            match self.last_error() {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's identity keys is too small!")
                }
                _ => panic!("Unknown error occured while getting OlmAccount's identity keys!"),
            }
        }

        identity_keys_result
    }

    /// Returns the last error that occured for an OlmAccount.
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmAccountError::Unknown is returned on an unknown error code.
    fn last_error(&self) -> OlmAccountError {
        let error;
        // get CString error code and convert to String
        unsafe {
            let error_raw = olm_sys::olm_account_last_error(self.olm_account_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

        match error {
            "NOT_ENOUGH_RANDOM" => OlmAccountError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmAccountError::OutputBufferTooSmall,
            _ => OlmAccountError::Unknown,
        }
    }

    /// Returns the signature of the supplied byte slice
    pub fn sign_bytes(&self, input_buf: &mut [u8]) -> String {
        let signature_result;
        let signature_error;
        unsafe {
            let input_ptr = input_buf.as_mut_ptr() as *mut _;
            let signature_len = olm_sys::olm_account_signature_length(self.olm_account_ptr);
            let mut signature_buf: Vec<u8> = vec![0; signature_len];
            let signature_ptr = signature_buf.as_mut_ptr() as *mut _;

            signature_error = olm_sys::olm_account_sign(
                self.olm_account_ptr,
                input_ptr,
                input_buf.len(),
                signature_ptr,
                signature_len,
            );

            mem::forget(signature_buf);

            signature_result =
                String::from_raw_parts(signature_ptr as *mut u8, signature_len, signature_len);
        }

        if signature_error == errors::olm_error() {
            match self.last_error() {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's signature is too small!")
                }
                _ => panic!("Unknown error occured while getting OlmAccount's identity keys!"),
            }
        }

        signature_result
    }

    /// Convenience function that converts the UTF-8 message
    /// to bytes and then calls sign_bytes(), returning its output.
    pub fn sign_utf8_msg(&self, msg: &mut str) -> String {
        unsafe { self.sign_bytes(msg.as_bytes_mut()) }
    }
}
