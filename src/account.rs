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

use crate::errors;
use crate::errors::OlmAccountError;
use crate::session::OlmSession;
use crate::PicklingMode;
use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;

/// An olm account manages all cryptographic keys used on a device.
/// ```
/// use olm_rs::account::OlmAccount;
///
/// let olm_account = OlmAccount::new();
/// println!("{}", olm_account.identity_keys());
/// ```
pub struct OlmAccount {
    // Pointer by which libolm acquires the data saved in an instance of OlmAccount
    pub olm_account_ptr: *mut olm_sys::OlmAccount,
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
        // allocate buffer for OlmAccount to be written into
        let olm_account_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_account_size() }];
        let olm_account_buf_ptr = Box::into_raw(olm_account_buf.into_boxed_slice()) as *mut _;

        // let libolm populate the allocated memory
        let olm_account_ptr = unsafe { olm_sys::olm_account(olm_account_buf_ptr) };

        // determine optimal length of the random buffer
        let random_len = unsafe { olm_sys::olm_create_account_random_length(olm_account_ptr) };
        let mut random_buf: Vec<u8> = vec![0; random_len];
        {
            let rng = SystemRandom::new();
            rng.fill(random_buf.as_mut_slice()).unwrap();
        }
        let random_ptr = Box::into_raw(random_buf.into_boxed_slice());

        // create OlmAccount with supplied random data
        let create_error = unsafe {
            olm_sys::olm_create_account(olm_account_ptr, random_ptr as *mut _, random_len)
        };

        let _drop_random_buf: Box<[u8]> = unsafe { Box::from_raw(random_ptr as *mut _) };

        if create_error == errors::olm_error() {
            match Self::last_error(olm_account_ptr) {
                OlmAccountError::NotEnoughRandom => {
                    panic!("Insufficient random data for generating one time keys for OlmAccount!")
                }
                _ => unreachable!("olm_create_account only returns NOT_ENOUGH_RANDOM error"),
            }
        }
        OlmAccount { olm_account_ptr }
    }

    /// Serialises an `OlmAccount` to encrypted Base64.
    ///
    /// # C-API equivalent
    /// `olm_pickle_account`
    ///
    /// # Example
    /// ```
    /// use olm_rs::account::OlmAccount;
    /// use olm_rs::PicklingMode;
    ///
    /// let identity_keys;
    /// let olm_account = OlmAccount::new();
    /// identity_keys = olm_account.identity_keys();
    /// let pickled = olm_account.pickle(PicklingMode::Unencrypted);
    /// let olm_account_2 = OlmAccount::unpickle(pickled, PicklingMode::Unencrypted).unwrap();
    /// let identity_keys_2 = olm_account_2.identity_keys();
    ///
    /// assert_eq!(identity_keys, identity_keys_2);
    /// ```
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for OlmAccount's pickled buffer
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let pickled_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_pickle_account_length(self.olm_account_ptr) }];
        let pickled_len = pickled_buf.len();
        let pickled_ptr = Box::into_raw(pickled_buf.into_boxed_slice());

        let key = crate::convert_pickling_mode_to_key(mode);

        let pickle_error = unsafe {
            olm_sys::olm_pickle_account(
                self.olm_account_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_ptr as *mut _,
                pickled_len,
            )
        };

        let pickled_after: Box<[u8]> = unsafe { Box::from_raw(pickled_ptr) };
        let pickled_result = String::from_utf8(pickled_after.to_vec())
            .expect("Pickled OlmAccount isn't valid UTF-8");

        if pickle_error == errors::olm_error() {
            match Self::last_error(self.olm_account_ptr) {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for pickled OlmAccount is too small!")
                }
                _ => panic!("Unknown error occurred while pickling OlmAccount!"),
            }
        } else {
            pickled_result
        }
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an `OlmAccount`.
    ///
    /// # C-API equivalent
    /// `olm_unpickle_account`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the account was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, mode: PicklingMode) -> Result<Self, OlmAccountError> {
        let pickled_len = pickled.len();
        let pickled_buf = Box::new(unsafe { pickled.as_bytes_mut() });

        let olm_account_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_account_size() }];
        let olm_account_buf_ptr = Box::into_raw(olm_account_buf.into_boxed_slice()) as *mut _;
        let olm_account_ptr = unsafe { olm_sys::olm_account(olm_account_buf_ptr) };

        let key = crate::convert_pickling_mode_to_key(mode);

        let unpickle_error = unsafe {
            olm_sys::olm_unpickle_account(
                olm_account_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            )
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_account_ptr))
        } else {
            Ok(OlmAccount { olm_account_ptr })
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
    pub fn identity_keys(&self) -> String {
        // get buffer length of identity keys
        let keys_len = unsafe { olm_sys::olm_account_identity_keys_length(self.olm_account_ptr) };
        let identity_keys_buf: Vec<u8> = vec![0; keys_len];
        let identity_keys_ptr = Box::into_raw(identity_keys_buf.into_boxed_slice());

        // write keys data in the keys buffer
        let identity_keys_error = unsafe {
            olm_sys::olm_account_identity_keys(
                self.olm_account_ptr,
                identity_keys_ptr as *mut _,
                keys_len,
            )
        };

        // String is constructed from the keys buffer and memory is freed after exiting the scope.
        // No memory should be leaked.
        let identity_keys_after: Box<[u8]> = unsafe { Box::from_raw(identity_keys_ptr) };
        let identity_keys_result = String::from_utf8(identity_keys_after.to_vec())
            .expect("OlmAccount's identity keys aren't valid UTF-8");

        if identity_keys_error == errors::olm_error() {
            match Self::last_error(self.olm_account_ptr) {
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
    fn last_error(olm_account_ptr: *mut olm_sys::OlmAccount) -> OlmAccountError {
        let error;
        // get CString error code and convert to String
        unsafe {
            let error_raw = olm_sys::olm_account_last_error(olm_account_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

        match error {
            "BAD_ACCOUNT_KEY" => OlmAccountError::BadAccountKey,
            "BAD_MESSAGE_KEY_ID" => OlmAccountError::BadMessageKeyId,
            "INVALID_BASE64" => OlmAccountError::InvalidBase64,
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
    pub fn sign(&self, message: &str) -> String {
        let message_buf = message.as_bytes();
        let message_ptr = message_buf.as_ptr() as *const _;

        let signature_len = unsafe { olm_sys::olm_account_signature_length(self.olm_account_ptr) };
        let signature_buf: Vec<u8> = vec![0; signature_len];
        let signature_ptr = Box::into_raw(signature_buf.into_boxed_slice());

        let signature_error = unsafe {
            olm_sys::olm_account_sign(
                self.olm_account_ptr,
                message_ptr,
                message_buf.len(),
                signature_ptr as *mut _,
                signature_len,
            )
        };

        let signature_after: Box<[u8]> = unsafe { Box::from_raw(signature_ptr) };
        let signature_result = String::from_utf8(signature_after.into_vec())
            .expect("Signature from OlmAccount isn't valid UTF-8");

        if signature_error == errors::olm_error() {
            match Self::last_error(self.olm_account_ptr) {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's signature is too small!")
                }
                _ => panic!("Unknown error occurred while getting OlmAccount's identity keys!"),
            }
        }

        signature_result
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
    pub fn generate_one_time_keys(&self, number_of_keys: usize) {
        // Get correct length for the random buffer
        let random_len = unsafe {
            olm_sys::olm_account_generate_one_time_keys_random_length(
                self.olm_account_ptr,
                number_of_keys,
            )
        };

        // Construct and populate random buffer
        let mut random_buf: Vec<u8> = vec![0; random_len];
        {
            let rng = SystemRandom::new();
            rng.fill(random_buf.as_mut_slice()).unwrap();
        }
        let random_ptr = Box::into_raw(random_buf.into_boxed_slice());

        // Call function for generating one time keys
        let generate_error = unsafe {
            olm_sys::olm_account_generate_one_time_keys(
                self.olm_account_ptr,
                number_of_keys,
                random_ptr as *mut _,
                random_len,
            )
        };

        let _drop_random: Box<[u8]> = unsafe { Box::from_raw(random_ptr) };

        if generate_error == errors::olm_error() {
            match Self::last_error(self.olm_account_ptr) {
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
    pub fn one_time_keys(&self) -> String {
        // get buffer length of OTKs
        let otks_len = unsafe { olm_sys::olm_account_one_time_keys_length(self.olm_account_ptr) };
        let otks_buf: Vec<u8> = vec![0; otks_len];
        let otks_ptr = Box::into_raw(otks_buf.into_boxed_slice());

        // write OTKs data in the OTKs buffer
        let otks_error = unsafe {
            olm_sys::olm_account_one_time_keys(self.olm_account_ptr, otks_ptr as *mut _, otks_len)
        };

        // String is constructed from the OTKs buffer and memory is freed after exiting the scope.
        let otks_after: Box<[u8]> = unsafe { Box::from_raw(otks_ptr) };
        let otks_result = String::from_utf8(otks_after.to_vec())
            .expect("OlmAccount's one time keys aren't valid UTF-8");

        if otks_error == errors::olm_error() {
            match Self::last_error(self.olm_account_ptr) {
                OlmAccountError::OutputBufferTooSmall => {
                    panic!("Buffer for OlmAccount's one time keys is too small!")
                }
                _ => panic!("Unknown error occurred while getting OlmAccount's one time keys!"),
            }
        }

        otks_result
    }

    /// Mark the current set of one time keys as published.
    ///
    /// # C-API equivalent
    /// `olm_account_mark_keys_as_published`
    ///
    pub fn mark_keys_as_published(&self) {
        unsafe {
            olm_sys::olm_account_mark_keys_as_published(self.olm_account_ptr);
        }
    }

    /// Remove the one time key used to create the supplied session.
    ///
    /// # C-API equivalent
    /// `olm_remove_one_time_keys`
    ///
    /// # Errors
    /// * `BAD_MESSAGE_KEY_ID` when the account doesn't hold a matching one time key
    ///
    pub fn remove_one_time_keys(&self, session: &OlmSession) -> Result<(), OlmAccountError> {
        let remove_error = unsafe {
            olm_sys::olm_remove_one_time_keys(self.olm_account_ptr, session.olm_session_ptr)
        };

        if remove_error == errors::olm_error() {
            Err(Self::last_error(self.olm_account_ptr))
        } else {
            Ok(())
        }
    }
}

impl Default for OlmAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        let _olm_account_buf: Box<olm_sys::OlmAccount> = unsafe {
            olm_sys::olm_clear_account(self.olm_account_ptr);
            // make Rust aware of the allocated memory again,
            // so it gets freed after going out of scope
            Box::from_raw(self.olm_account_ptr)
        };
    }
}
