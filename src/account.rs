// Copyright 2020 Johannes Hayeß
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module wraps around all functions following the pattern `olm_account_*`.

use crate::errors;
use crate::errors::{OlmAccountError, OlmSessionError};
use crate::getrandom;
use crate::session::OlmSession;
use crate::PicklingMode;
use olm_sys;
use std::ffi::CStr;

#[cfg(feature = "deserialization")]
use serde::Deserialize;
#[cfg(feature = "deserialization")]
use std::collections::HashMap;

/// An olm account manages all cryptographic keys used on a device.
/// ```
/// use olm_rs::account::OlmAccount;
///
/// let olm_account = OlmAccount::new();
/// println!("{:?}", olm_account.identity_keys());
/// ```
pub struct OlmAccount {
    /// Pointer by which libolm acquires the data saved in an instance of OlmAccount
    pub(crate) olm_account_ptr: *mut olm_sys::OlmAccount,
    #[used]
    olm_account_buf: Vec<u8>,
}

#[cfg(feature = "deserialization")]
/// Struct representing the parsed result of `OlmAccount::identity_keys()`.
#[derive(Deserialize, Debug, PartialEq)]
pub struct IdentityKeys {
    #[serde(flatten)]
    keys: HashMap<String, String>,
}

#[cfg(feature = "deserialization")]
impl IdentityKeys {
    pub fn ed25519(&self) -> &str {
        &self.keys["ed25519"]
    }
    pub fn curve25519(&self) -> &str {
        &self.keys["curve25519"]
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        let ret = self.keys.get(k);
        ret.map(|x| &**x)
    }
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
        let mut olm_account_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_account_size() }];

        // let libolm populate the allocated memory
        let olm_account_ptr =
            unsafe { olm_sys::olm_account(olm_account_buf.as_mut_ptr() as *mut _) };

        // determine optimal length of the random buffer
        let random_len = unsafe { olm_sys::olm_create_account_random_length(olm_account_ptr) };
        let mut random_buf: Vec<u8> = vec![0; random_len];
        getrandom(&mut random_buf);

        // create OlmAccount with supplied random data
        let create_error = unsafe {
            olm_sys::olm_create_account(
                olm_account_ptr,
                random_buf.as_mut_ptr() as *mut _,
                random_len,
            )
        };

        if create_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(olm_account_ptr));
        }
        OlmAccount {
            olm_account_ptr,
            olm_account_buf,
        }
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
    /// * on malformed UTF-8 coding for pickling provided by libolm
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let mut pickled_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_pickle_account_length(self.olm_account_ptr) }];

        let key = crate::convert_pickling_mode_to_key(mode);

        let pickle_error = unsafe {
            olm_sys::olm_pickle_account(
                self.olm_account_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_buf.len(),
            )
        };

        let pickled_result = String::from_utf8(pickled_buf).unwrap();

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        pickled_result
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

        let mut olm_account_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_account_size() }];
        let olm_account_ptr =
            unsafe { olm_sys::olm_account(olm_account_buf.as_mut_ptr() as *mut _) };

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
            Ok(OlmAccount {
                olm_account_ptr,
                olm_account_buf,
            })
        }
    }

    pub(crate) fn identity_keys_helper(&self) -> String {
        // get buffer length of identity keys
        let keys_len = unsafe { olm_sys::olm_account_identity_keys_length(self.olm_account_ptr) };
        let mut identity_keys_buf: Vec<u8> = vec![0; keys_len];

        // write keys data in the keys buffer
        let identity_keys_error = unsafe {
            olm_sys::olm_account_identity_keys(
                self.olm_account_ptr,
                identity_keys_buf.as_mut_ptr() as *mut _,
                keys_len,
            )
        };

        // String is constructed from the keys buffer and memory is freed after exiting the scope.
        // No memory should be leaked.
        let identity_keys_result = String::from_utf8(identity_keys_buf).unwrap();

        if identity_keys_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }

        identity_keys_result
    }

    /// Returns the account's public identity keys already formatted as JSON and BASE64.
    ///
    /// # C-API equivalent
    /// `olm_account_identity_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied identity keys buffer
    /// * on malformed UTF-8 coding of the identity keys provided by libolm
    ///
    #[cfg(not(feature = "deserialization"))]
    pub fn identity_keys(&self) -> String {
        self.identity_keys_helper()
    }

    #[cfg(feature = "deserialization")]
    pub fn identity_keys(&self) -> IdentityKeys {
        let deserialized: IdentityKeys = serde_json::from_str(&self.identity_keys_helper())
            .expect("Can't deserialize identity keys");
        deserialized
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
    /// * on malformed UTF-8 coding of the signature provided by libolm
    ///
    pub fn sign(&self, message: &str) -> String {
        let message_buf = message.as_bytes();
        let message_ptr = message_buf.as_ptr() as *const _;

        let signature_len = unsafe { olm_sys::olm_account_signature_length(self.olm_account_ptr) };
        let mut signature_buf: Vec<u8> = vec![0; signature_len];

        let signature_error = unsafe {
            olm_sys::olm_account_sign(
                self.olm_account_ptr,
                message_ptr,
                message_buf.len(),
                signature_buf.as_mut_ptr() as *mut _,
                signature_len,
            )
        };

        let signature_result = String::from_utf8(signature_buf).unwrap();

        if signature_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
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
        getrandom(&mut random_buf);

        // Call function for generating one time keys
        let generate_error = unsafe {
            olm_sys::olm_account_generate_one_time_keys(
                self.olm_account_ptr,
                number_of_keys,
                random_buf.as_mut_ptr() as *mut _,
                random_len,
            )
        };

        if generate_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
        }
    }

    /// Gets the OlmAccount's one time keys formatted as JSON.
    ///
    /// # C-API equivalent
    /// `olm_account_one_time_keys`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied one time keys buffer
    /// * on malformed UTF-8 coding of the keys provided by libolm
    ///
    pub fn one_time_keys(&self) -> String {
        // get buffer length of OTKs
        let otks_len = unsafe { olm_sys::olm_account_one_time_keys_length(self.olm_account_ptr) };
        let mut otks_buf: Vec<u8> = vec![0; otks_len];

        // write OTKs data in the OTKs buffer
        let otks_error = unsafe {
            olm_sys::olm_account_one_time_keys(
                self.olm_account_ptr,
                otks_buf.as_mut_ptr() as *mut _,
                otks_len,
            )
        };

        // String is constructed from the OTKs buffer and memory is freed after exiting the scope.
        let otks_result = String::from_utf8(otks_buf).unwrap();

        if otks_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_account_ptr));
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

    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session(
        &self,
        one_time_key_message: String,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_inbound_session(self, one_time_key_message)
    }

    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session_from(
        &self,
        their_identity_key: &str,
        one_time_key_message: String,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_inbound_session_from(self, their_identity_key, one_time_key_message)
    }

    /// Creates an outbound session for sending messages to a specific
    /// identity and one time key.
    ///
    /// # Errors
    /// * `InvalidBase64` for invalid base64 coding on supplied arguments
    ///
    /// # Panics
    /// * `NotEnoughRandom` if not enough random data was supplied
    ///
    pub fn create_outbound_session(
        &self,
        their_identity_key: &str,
        their_one_time_key: &str,
    ) -> Result<OlmSession, OlmSessionError> {
        OlmSession::create_outbound_session(self, their_identity_key, their_one_time_key)
    }
}

impl Default for OlmAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_account(self.olm_account_ptr);
        }
    }
}

#[cfg(feature = "deserialization")]
#[test]
fn parsed_keys() {
    let account = OlmAccount::new();
    let identity_keys = json::parse(&account.identity_keys_helper()).unwrap();
    let identity_keys_parsed = account.identity_keys();
    assert_eq!(
        identity_keys_parsed.curve25519(),
        identity_keys["curve25519"]
    );
    assert_eq!(identity_keys_parsed.ed25519(), identity_keys["ed25519"]);
}
