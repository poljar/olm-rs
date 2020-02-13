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

//! This module wraps around all functions following the pattern `olm_session_*`,
//! as well as functions for encryption and decryption using the Double Ratchet algorithm.

use crate::account::OlmAccount;
use crate::errors;
use crate::errors::OlmSessionError;
use crate::PicklingMode;
use getrandom::getrandom;
use olm_sys;
use std::cmp::Ordering;
use std::ffi::CStr;

/// Either an outbound or inbound session for secure communication.
#[derive(Eq)]
pub struct OlmSession {
    pub(crate) olm_session_ptr: *mut olm_sys::OlmSession,
    #[used]
    olm_session_buf: Vec<u8>,
}

impl OlmSession {
    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// # C-API equivalent
    /// `olm_create_inbound_session`
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session(
        account: &OlmAccount,
        mut one_time_key_message: String,
    ) -> Result<Self, OlmSessionError> {
        Self::create_session_with(|olm_session_ptr| unsafe {
            let one_time_key_message_buf = one_time_key_message.as_bytes_mut();
            olm_sys::olm_create_inbound_session(
                olm_session_ptr,
                account.olm_account_ptr,
                one_time_key_message_buf.as_mut_ptr() as *mut _,
                one_time_key_message_buf.len(),
            )
        })
    }

    /// Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    ///
    /// # C-API equivalent
    /// `olm_create_inbound_session_from`
    ///
    /// # Errors
    /// * `InvalidBase64`
    /// * `BadMessageVersion`
    /// * `BadMessageFormat`
    /// * `BadMessageKeyId`
    ///
    pub fn create_inbound_session_from(
        account: &OlmAccount,
        their_identity_key: &str,
        mut one_time_key_message: String,
    ) -> Result<Self, OlmSessionError> {
        Self::create_session_with(|olm_session_ptr| {
            let their_identity_key_buf = their_identity_key.as_bytes();
            unsafe {
                let one_time_key_message_buf = one_time_key_message.as_bytes_mut();
                olm_sys::olm_create_inbound_session_from(
                    olm_session_ptr,
                    account.olm_account_ptr,
                    their_identity_key_buf.as_ptr() as *const _,
                    their_identity_key_buf.len(),
                    one_time_key_message_buf.as_mut_ptr() as *mut _,
                    one_time_key_message_buf.len(),
                )
            }
        })
    }

    /// Creates an outbound session for sending messages to a specific
    /// identity and one time key.
    ///
    /// # C-API equivalent
    /// `olm_create_outbound_session`
    ///
    /// # Errors
    /// * `InvalidBase64` for invalid base64 coding on supplied arguments
    ///
    /// # Panics
    /// * `NotEnoughRandom` if not enough random data was supplied
    ///
    pub fn create_outbound_session(
        account: &OlmAccount,
        their_identity_key: &str,
        their_one_time_key: &str,
    ) -> Result<Self, OlmSessionError> {
        Self::create_session_with(|olm_session_ptr| {
            let their_identity_key_buf = their_identity_key.as_bytes();
            let their_one_time_key_buf = their_one_time_key.as_bytes();
            let random_len =
                unsafe { olm_sys::olm_create_outbound_session_random_length(olm_session_ptr) };
            let mut random_buf: Vec<u8> = vec![0; random_len];
            let _ = getrandom(random_buf.as_mut_slice());

            unsafe {
                olm_sys::olm_create_outbound_session(
                    olm_session_ptr,
                    account.olm_account_ptr,
                    their_identity_key_buf.as_ptr() as *const _,
                    their_identity_key_buf.len(),
                    their_one_time_key_buf.as_ptr() as *const _,
                    their_one_time_key_buf.len(),
                    random_buf.as_mut_ptr() as *mut _,
                    random_len,
                )
            }
        })
    }

    /// Helper function for creating new sessions and handling errors.
    fn create_session_with<F: FnMut(*mut olm_sys::OlmSession) -> usize>(
        mut f: F,
    ) -> Result<OlmSession, OlmSessionError> {
        let mut olm_session_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_session_size() }];

        let olm_session_ptr =
            unsafe { olm_sys::olm_session(olm_session_buf.as_mut_ptr() as *mut _) };
        let error = f(olm_session_ptr);
        if error == errors::olm_error() {
            let last_error = Self::last_error(olm_session_ptr);
            if last_error == OlmSessionError::NotEnoughRandom {
                errors::handle_fatal_error(OlmSessionError::NotEnoughRandom);
            }

            Err(last_error)
        } else {
            Ok(OlmSession {
                olm_session_ptr,
                olm_session_buf,
            })
        }
    }

    /// Gives you the last error encountered by the `OlmSession` given as an argument.
    fn last_error(session_ptr: *mut olm_sys::OlmSession) -> OlmSessionError {
        // get CString error code and convert to String
        let error_raw = unsafe { olm_sys::olm_session_last_error(session_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_ACCOUNT_KEY" => OlmSessionError::BadAccountKey,
            "BAD_MESSAGE_MAC" => OlmSessionError::BadMessageMac,
            "BAD_MESSAGE_FORMAT" => OlmSessionError::BadMessageFormat,
            "BAD_MESSAGE_KEY_ID" => OlmSessionError::BadMessageKeyId,
            "BAD_MESSAGE_VERSION" => OlmSessionError::BadMessageVersion,
            "INVALID_BASE64" => OlmSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmSessionError::OutputBufferTooSmall,
            _ => OlmSessionError::Unknown,
        }
    }

    /// Retuns the identifier for this session. Will be the same for both ends of the conversation.
    ///
    /// # C-API equivalent
    /// `olm_session_id`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` if the supplied output buffer for the ID was too small
    /// * on malformed UTF-8 coding of the session ID provided by libolm
    ///
    pub fn session_id(&self) -> String {
        let session_id_len = unsafe { olm_sys::olm_session_id_length(self.olm_session_ptr) };
        let mut session_id_buf: Vec<u8> = vec![0; session_id_len];

        let error = unsafe {
            olm_sys::olm_session_id(
                self.olm_session_ptr,
                session_id_buf.as_mut_ptr() as *mut _,
                session_id_len,
            )
        };

        let session_id_result = String::from_utf8(session_id_buf).unwrap();

        if error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_session_ptr));
        }

        session_id_result
    }

    /// Serialises an `OlmSession` to encrypted base64.
    ///
    /// # C-API equivalent
    /// `olm_pickle_session`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for OlmSession's pickled buffer
    /// * on malformed UTF-8 coding of the pickling provided by libolm
    ///
    pub fn pickle(&self, mode: PicklingMode) -> String {
        let pickled_len = unsafe { olm_sys::olm_pickle_session_length(self.olm_session_ptr) };
        let mut pickled_buf = vec![0; pickled_len];

        let key = crate::convert_pickling_mode_to_key(mode);

        let pickle_error = unsafe {
            olm_sys::olm_pickle_session(
                self.olm_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            )
        };

        let pickled_result = String::from_utf8(pickled_buf).unwrap();

        if pickle_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_session_ptr));
        }

        pickled_result
    }

    /// Deserialises from encrypted base64 that was previously obtained by pickling an `OlmSession`.
    ///
    /// # C-API equivalent
    /// `olm_unpickle_session`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the session was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, mode: PicklingMode) -> Result<Self, OlmSessionError> {
        let key = crate::convert_pickling_mode_to_key(mode);

        Self::create_session_with(|olm_session_ptr| {
            let pickled_len = pickled.len();
            unsafe {
                let pickled_buf = pickled.as_bytes_mut();

                olm_sys::olm_unpickle_session(
                    olm_session_ptr,
                    key.as_ptr() as *const _,
                    key.len(),
                    pickled_buf.as_mut_ptr() as *mut _,
                    pickled_len,
                )
            }
        })
    }

    /// Encrypts a plaintext message using the session.
    ///
    /// # C-API equivalent
    /// * `olm_encrypt`
    ///
    /// # Panics
    /// * `NotEnoughRandom` for too little supplied random data
    /// * `OutputBufferTooSmall` for encrypted message
    /// * on malformed UTF-8 coding of the ciphertext provided by libolm
    ///
    pub fn encrypt(&self, plaintext: &str) -> String {
        let plaintext_buf = plaintext.as_bytes();
        let plaintext_len = plaintext_buf.len();
        let message_len =
            unsafe { olm_sys::olm_encrypt_message_length(self.olm_session_ptr, plaintext_len) };
        let mut message_buf: Vec<u8> = vec![0; message_len];

        let random_len = unsafe { olm_sys::olm_encrypt_random_length(self.olm_session_ptr) };
        let mut random_buf: Vec<u8> = vec![0; random_len];
        let _ = getrandom(random_buf.as_mut_slice());

        let encrypt_error = unsafe {
            olm_sys::olm_encrypt(
                self.olm_session_ptr,
                plaintext_buf.as_ptr() as *const _,
                plaintext_len,
                random_buf.as_mut_ptr() as *mut _,
                random_len,
                message_buf.as_mut_ptr() as *mut _,
                message_len,
            )
        };

        let message_result = String::from_utf8(message_buf).unwrap();

        if encrypt_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_session_ptr));
        }

        message_result
    }

    /// Decrypts a message using this session. Decoding is lossy, meaing if
    /// the decrypted plaintext contains invalid UTF-8 symbols, they will
    /// be returned as `U+FFFD` (�).
    ///
    /// # C-API equivalent
    /// `olm_decrypt`
    ///
    /// # Errors
    /// * `InvalidBase64` on invalid base64 coding for supplied arguments
    /// * `BadMessageVersion` on unsupported protocol version
    /// * `BadMessageFormat` on failing to decode the message
    /// * `BadMessageMac` on invalid message MAC
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` on plaintext output buffer
    ///
    pub fn decrypt(
        &self,
        message_type: OlmMessageType,
        mut message: String,
    ) -> Result<String, OlmSessionError> {
        // get the usize value associated with the supplied message type
        let message_type_val = match message_type {
            OlmMessageType::PreKey => olm_sys::OLM_MESSAGE_TYPE_PRE_KEY,
            _ => olm_sys::OLM_MESSAGE_TYPE_MESSAGE,
        };

        // We need to clone the message because
        // olm_decrypt_max_plaintext_length destroys the input buffer
        let mut message_for_len = message.clone();
        let message_buf = unsafe { message_for_len.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;

        let plaintext_max_len = unsafe {
            olm_sys::olm_decrypt_max_plaintext_length(
                self.olm_session_ptr,
                message_type_val,
                message_ptr,
                message_len,
            )
        };
        if plaintext_max_len == errors::olm_error() {
            return Err(Self::last_error(self.olm_session_ptr));
        }

        let mut plaintext_buf: Vec<u8> = vec![0; plaintext_max_len];

        let message_buf = unsafe { message.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;

        let plaintext_result_len = unsafe {
            olm_sys::olm_decrypt(
                self.olm_session_ptr,
                message_type_val,
                message_ptr,
                message_len,
                plaintext_buf.as_mut_ptr() as *mut _,
                plaintext_max_len,
            )
        };

        let decrypt_error = plaintext_result_len;
        if decrypt_error == errors::olm_error() {
            let last_error = Self::last_error(self.olm_session_ptr);
            if last_error == OlmSessionError::OutputBufferTooSmall {
                errors::handle_fatal_error(OlmSessionError::OutputBufferTooSmall);
            }
            return Err(last_error);
        }

        plaintext_buf.truncate(plaintext_result_len);
        Ok(String::from_utf8_lossy(&plaintext_buf).to_string())
    }

    /// The type of the next message that will be returned from encryption.
    ///
    /// # C-API equivalent
    /// `olm_encrypt_message_type`
    ///
    /// # Panics
    /// Can apperently encounter a fatal error, but the documentation does not specifiy
    /// what kind of error.
    ///
    pub fn encrypt_message_type(&self) -> OlmMessageType {
        let message_type_result =
            unsafe { olm_sys::olm_encrypt_message_type(self.olm_session_ptr) };

        // returns either result or error
        let message_type_error = message_type_result;

        if message_type_error == errors::olm_error() {
            errors::handle_fatal_error(Self::last_error(self.olm_session_ptr));
        }

        match message_type_result {
            olm_sys::OLM_MESSAGE_TYPE_PRE_KEY => OlmMessageType::PreKey,
            _ => OlmMessageType::Message,
        }
    }

    /// Checker for any received messages for this session.
    ///
    /// # C-API equivalent
    /// `olm_session_has_received_message`
    ///
    pub fn has_received_message(&self) -> bool {
        // To get the bool value of an int_c type, check for inequality with zero.
        //
        // Truth table:
        // +-----------+----------+------+
        // |Orig. value|Expression|Result|
        // +-----------+----------+------+
        // |0          |0 != 0    |false |
        // +-----------+----------+------+
        // |1          |0 != 1    |true  |
        // +-----------+----------+------+

        0 != unsafe { olm_sys::olm_session_has_received_message(self.olm_session_ptr) }
    }

    /// Checks if the 'prekey' message is for this in-bound session.
    ///
    /// # C-API equivalent
    /// `olm_matches_inbound_session`
    ///
    /// # Errors
    /// * `InvalidBase64` for failing to decode base64 in `one_time_key_message`
    /// * `BadMessageVersion` for message from unsupported protocol version
    /// * `BadMessageFormat` for failing to decode `one_time_key_message`
    ///
    pub fn matches_inbound_session(
        &self,
        mut one_time_key_message: String,
    ) -> Result<bool, OlmSessionError> {
        let one_time_key_message_buf = unsafe { one_time_key_message.as_bytes_mut() };
        let matches_result = unsafe {
            olm_sys::olm_matches_inbound_session(
                self.olm_session_ptr,
                one_time_key_message_buf.as_mut_ptr() as *mut _,
                one_time_key_message_buf.len(),
            )
        };

        // value returned by libolm can be both result and error
        let matches_error = matches_result;
        if matches_error == errors::olm_error() {
            Err(OlmSession::last_error(self.olm_session_ptr))
        } else {
            match matches_result {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(OlmSessionError::Unknown),
            }
        }
    }

    /// Checks if the 'prekey' message is for this in-bound session.
    ///
    /// # C-API equivalent
    /// `olm_matches_inbound_session`
    ///
    /// # Errors
    /// * `InvalidBase64` for failing to decode base64 in `one_time_key_message`
    /// * `BadMessageVersion` for message from unsupported protocol version
    /// * `BadMessageFormat` for failing to decode `one_time_key_message`
    ///
    pub fn matches_inbound_session_from(
        &self,
        their_identity_key: &str,
        mut one_time_key_message: String,
    ) -> Result<bool, OlmSessionError> {
        let their_identity_key_buf = their_identity_key.as_bytes();
        let their_identity_key_ptr = their_identity_key_buf.as_ptr() as *const _;
        let one_time_key_message_buf = unsafe { one_time_key_message.as_bytes_mut() };
        let matches_result = unsafe {
            olm_sys::olm_matches_inbound_session_from(
                self.olm_session_ptr,
                their_identity_key_ptr,
                their_identity_key_buf.len(),
                one_time_key_message_buf.as_mut_ptr() as *mut _,
                one_time_key_message_buf.len(),
            )
        };

        // value returned by libolm can be both result and error
        let matches_error = matches_result;
        if matches_error == errors::olm_error() {
            Err(OlmSession::last_error(self.olm_session_ptr))
        } else {
            match matches_result {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(OlmSessionError::Unknown),
            }
        }
    }
}

/// The message types that are returned after encryption.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OlmMessageType {
    PreKey,
    Message,
}

/// orders by unicode code points (which is a superset of ASCII)
impl Ord for OlmSession {
    fn cmp(&self, other: &Self) -> Ordering {
        self.session_id().cmp(&other.session_id())
    }
}

impl PartialOrd for OlmSession {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OlmSession {
    fn eq(&self, other: &Self) -> bool {
        self.session_id() == other.session_id()
    }
}

impl Drop for OlmSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_session(self.olm_session_ptr);
        }
    }
}
