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

//! This module wraps around all functions following the pattern `olm_account_*`.

use errors;
use errors::OlmAccountError;
use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;
use std::mem;

/// An olm account manages all cryptographic keys used on a device.
pub struct OlmAccount {
    // Reserved memory buffer holding data of an OlmAccount for libolm
    _olm_account_buf: Vec<u8>,
    // Pointer by which libolm acquires the data saved in an instance of OlmAccount
    olm_account_ptr: *mut olm_sys::OlmAccount,
}

impl OlmAccount {
    /// Creates a new instance of OlmAccount. During the instantiation the Ed25519 fingerprint key pair
    /// and the Curve25519 identity key pair are generated. For more information see
    /// [here](https://matrix.org/docs/guides/e2e_implementation.html#keys-used-in-end-to-end-encryption).
    ///
    /// # C-API equivalent
    /// `olm_create_account`
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM` for OlmAccount's creation
    ///
    pub fn new() -> Self {
        let olm_account_ptr;
        let mut olm_account_buf: Vec<u8>;
        let create_error;
        unsafe {
            // allocate buffer for OlmAccount to be written into
            olm_account_buf = vec![0; olm_sys::olm_account_size()];
            olm_account_ptr = olm_sys::olm_account(olm_account_buf.as_mut_ptr() as *mut _);

            // determine optimal length of the random buffer
            let random_len = olm_sys::olm_create_account_random_length(olm_account_ptr);
            let mut random_buf: Vec<u8> = vec![0; random_len];
            {
                let rng = SystemRandom::new();
                rng.fill(random_buf.as_mut_slice()).unwrap();
            }

            let random_ptr = random_buf.as_mut_ptr() as *mut _;
            create_error = olm_sys::olm_create_account(olm_account_ptr, random_ptr, random_len);
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
    ///
    /// # C-API equivalent
    /// `olm_account_identity_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied identity keys buffer
    ///
    pub fn identity_keys(&mut self) -> String {
        let identity_keys_result: String;
        let identity_keys_error;
        unsafe {
            // get buffer length of identity keys
            let keys_len = olm_sys::olm_account_identity_keys_length(self.olm_account_ptr);
            let mut identity_keys_buf: Vec<u8> = vec![0; keys_len];
            let identity_keys_ptr = identity_keys_buf.as_mut_ptr() as *mut _;

            // write keys data in the keys buffer
            identity_keys_error = olm_sys::olm_account_identity_keys(
                self.olm_account_ptr,
                identity_keys_ptr,
                keys_len,
            );

            // To avoid a double memory free we have to forget about our buffer,
            // since we are using the buffer's data to construct the final string below.
            mem::forget(identity_keys_buf);

            // String is constructed from the keys buffer and memory is freed after exiting the scope.
            // No memory should be leaked.
            identity_keys_result =
                String::from_raw_parts(identity_keys_ptr as *mut u8, keys_len, keys_len);
        }

        if identity_keys_error == errors::olm_error() {
            match self.last_error() {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's identity keys is too small!")
                }
                _ => panic!("Unknown error occurred while getting OlmAccount's identity keys!"),
            }
        }

        identity_keys_result
    }

    /// Returns the last error that occurred for an OlmAccount.
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

    /// Returns the signature of the supplied byte slice.
    ///
    /// # C-API equivalent
    /// `olm_account_sign`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied signature buffer
    ///
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
                _ => panic!("Unknown error occurred while getting OlmAccount's identity keys!"),
            }
        }

        signature_result
    }

    /// Convenience function that converts the UTF-8 message
    /// to bytes and then calls `sign_bytes()`, returning its output.
    pub fn sign_utf8_msg(&self, msg: &mut str) -> String {
        unsafe { self.sign_bytes(msg.as_bytes_mut()) }
    }

    /// Maximum number of one time keys that this OlmAccount can currently hold.
    ///
    /// # C-API equivalent
    /// `olm_account_max_number_of_one_time_keys`
    ///
    pub fn max_number_of_one_time_keys(&self) -> usize {
        unsafe { olm_sys::olm_account_max_number_of_one_time_keys(self.olm_account_ptr) }
    }

    /// Generates the supplied number of one time keys.
    ///
    /// # C-API equivalent
    /// `olm_account_generate_one_time_keys`
    ///
    /// # Panics
    /// * `NOT_ENOUGH_RANDOM` for the creation of one time keys
    ///
    pub fn generate_one_time_keys(&mut self, number_of_keys: usize) {
        let generate_error;
        unsafe {
            // Get correct length for the random buffer
            let random_len = olm_sys::olm_account_generate_one_time_keys_random_length(
                self.olm_account_ptr,
                number_of_keys,
            );

            // Construct and populate random buffer
            let mut random_buf: Vec<u8> = vec![0; random_len];
            {
                let rng = SystemRandom::new();
                rng.fill(random_buf.as_mut_slice()).unwrap();
            }
            let random_ptr = random_buf.as_mut_ptr() as *mut _;

            // Call function for generating one time keys
            generate_error = olm_sys::olm_account_generate_one_time_keys(
                self.olm_account_ptr,
                number_of_keys,
                random_ptr,
                random_len,
            );
        }

        if generate_error == errors::olm_error() {
            match self.last_error() {
                OlmAccountError::NotEnoughRandom => {
                    panic!("Insufficient random data for generating one time keys for OlmAccount!")
                }
                _ => {
                    panic!("Unknown error occurred, while generating one time keys for OlmAccount!")
                }
            }
        }
    }

    /// Gets the OlmAccount's one time keys formatted as JSON.
    ///
    /// # C-API equivalent
    /// `olm_account_one_time_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied one time keys buffer
    ///
    pub fn one_time_keys(&mut self) -> String {
        let otks_result: String;
        let otks_error;
        unsafe {
            // get buffer length of OTKs
            let otks_len = olm_sys::olm_account_one_time_keys_length(self.olm_account_ptr);
            let mut otks_buf: Vec<u8> = vec![0; otks_len];
            let otks_ptr = otks_buf.as_mut_ptr() as *mut _;

            // write OTKs data in the OTKs buffer
            otks_error =
                olm_sys::olm_account_one_time_keys(self.olm_account_ptr, otks_ptr, otks_len);

            // To avoid a double memory free we have to forget about our buffer,
            // since we are using the buffer's data to construct the final string below.
            mem::forget(otks_buf);

            // String is constructed from the OTKs buffer and memory is freed after exiting the scope.
            // No memory should be leaked.
            otks_result = String::from_raw_parts(otks_ptr as *mut u8, otks_len, otks_len);
        }

        if otks_error == errors::olm_error() {
            match self.last_error() {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's one time keys is too small!")
                }
                _ => panic!("Unknown error occurred while getting OlmAccount's one time keys!"),
            }
        }

        otks_result
    }

    /// Mark the current set of keys as published.
    ///
    /// # C-API equivalent
    /// `olm_account_mark_keys_as_published`
    ///
    pub fn mark_keys_as_published(&mut self) {
        unsafe {
            olm_sys::olm_account_mark_keys_as_published(self.olm_account_ptr);
        }
    }
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_account(self.olm_account_ptr);
        }
    }
}
