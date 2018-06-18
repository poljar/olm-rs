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

//! This module wraps around all functions following the pattern `olm_session_*`,
//! as well as functions for encryption and decryption using the Double Ratchet algorithm.

use account::OlmAccount;
use errors;
use errors::OlmSessionError;
use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;
use std::mem;

/// Either an outbound or inbound session for secure communication.
pub struct OlmSession {
    _olm_session_buf: Vec<u8>,
    pub olm_session_ptr: *mut olm_sys::OlmSession,
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
        account: &mut OlmAccount,
        one_time_key_message: &mut str,
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
        account: &mut OlmAccount,
        their_identity_key: &str,
        one_time_key_message: &mut str,
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
        account: &mut OlmAccount,
        their_identity_key: &str,
        their_one_time_key: &str,
    ) -> Result<Self, OlmSessionError> {
        Self::create_session_with(|olm_session_ptr| {
            let their_identity_key_buf = their_identity_key.as_bytes();
            let their_one_time_key_buf = their_one_time_key.as_bytes();
            unsafe {
                let random_len =
                    olm_sys::olm_create_outbound_session_random_length(olm_session_ptr);
                let mut random_buf: Vec<u8> = vec![0; random_len];
                {
                    let rng = SystemRandom::new();
                    rng.fill(random_buf.as_mut_slice()).unwrap();
                }

                olm_sys::olm_create_outbound_session(
                    olm_session_ptr,
                    account.olm_account_ptr,
                    their_identity_key_buf.as_ptr() as *const _,
                    their_identity_key_buf.len(),
                    their_one_time_key_buf.as_ptr() as *const _,
                    their_one_time_key_buf.len(),
                    random_buf.as_mut_ptr() as *mut _,
                    random_buf.len(),
                )
            }
        })
    }

    /// Helper function for creating new sessions and handling errors.
    fn create_session_with<F: FnMut(*mut olm_sys::OlmSession) -> usize>(
        mut f: F,
    ) -> Result<OlmSession, OlmSessionError> {
        let olm_session_ptr;
        let mut olm_session_buf;
        let error;
        unsafe {
            olm_session_buf = vec![0; olm_sys::olm_session_size()];
            olm_session_ptr = olm_sys::olm_session(olm_session_buf.as_mut_ptr() as *mut _);
            error = f(olm_session_ptr);
        }
        if error == errors::olm_error() {
            if Self::last_error(olm_session_ptr) == OlmSessionError::NotEnoughRandom {
                panic!("Not enough random data supplied for creation of outbound session!");
            }
            Err(Self::last_error(olm_session_ptr))
        } else {
            Ok(OlmSession {
                _olm_session_buf: olm_session_buf,
                olm_session_ptr: olm_session_ptr,
            })
        }
    }

    /// Gives you the last error encountered by the `OlmSession` given as an argument.
    fn last_error(session_ptr: *mut olm_sys::OlmSession) -> OlmSessionError {
        let error;
        // get CString error code and convert to String
        unsafe {
            let error_raw = olm_sys::olm_session_last_error(session_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

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
    ///
    pub fn session_id(&mut self) -> String {
        let session_id_result;
        let error;

        unsafe {
            let session_id_len = olm_sys::olm_session_id_length(self.olm_session_ptr);
            let mut session_id_buf: Vec<u8> = vec![0; session_id_len];
            let session_id_ptr = session_id_buf.as_mut_ptr() as *mut _;

            error = olm_sys::olm_session_id(self.olm_session_ptr, session_id_ptr, session_id_len);

            mem::forget(session_id_buf);

            session_id_result =
                String::from_raw_parts(session_id_ptr as *mut u8, session_id_len, session_id_len);
        }

        if error == errors::olm_error() {
            match Self::last_error(self.olm_session_ptr) {
                OlmSessionError::OutputBufferTooSmall => {
                    panic!("Supplied output buffer for OlmSession's ID is too small!")
                }
                _ => panic!("Unknown error encountered when getting OlmSession's ID!"),
            }
        }

        session_id_result
    }

    /// Serialises an `OlmSession` to encrypted base64. The encryption key is free to choose
    /// (empty byte slice is allowed).
    ///
    /// # C-API equivalent
    /// `olm_pickle_session`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for OlmSession's pickled buffer
    ///
    pub fn pickle(&mut self, key: &[u8]) -> String {
        let pickled_result;
        let pickle_error;

        unsafe {
            let pickled_len = olm_sys::olm_pickle_session_length(self.olm_session_ptr);
            let mut pickled_buf = vec![0; pickled_len];
            let pickled_ptr = pickled_buf.as_mut_ptr() as *mut _;

            pickle_error = olm_sys::olm_pickle_session(
                self.olm_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_ptr,
                pickled_len,
            );

            mem::forget(pickled_buf);

            pickled_result =
                String::from_raw_parts(pickled_ptr as *mut u8, pickled_len, pickled_len);
        }

        if pickle_error == errors::olm_error() {
            match Self::last_error(self.olm_session_ptr) {
                OlmSessionError::OutputBufferTooSmall => {
                    panic!("Buffer for pickled OlmSession is too small!")
                }
                _ => panic!("Unknown error occurred while pickling OlmSession!"),
            }
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
    pub fn unpickle(pickled: &mut str, key: &[u8]) -> Result<Self, OlmSessionError> {
        Self::create_session_with(|olm_session_ptr| unsafe {
            let pickled_len = pickled.len();
            let pickled_buf = pickled.as_bytes_mut();

            olm_sys::olm_unpickle_session(
                olm_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            )
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
    ///
    pub fn encrypt(&mut self, plaintext: &str) -> String {
        let encrypt_error;
        let message_result;

        unsafe {
            let plaintext_buf = plaintext.as_bytes();
            let plaintext_len = plaintext_buf.len();
            let message_len =
                olm_sys::olm_encrypt_message_length(self.olm_session_ptr, plaintext_len);
            let mut message_buf: Vec<u8> = vec![0; message_len];
            let message_ptr = message_buf.as_mut_ptr() as *mut _;

            let random_len = olm_sys::olm_encrypt_random_length(self.olm_session_ptr);
            let mut random_buf: Vec<u8> = vec![0; random_len];
            {
                let rng = SystemRandom::new();
                rng.fill(random_buf.as_mut_slice()).unwrap();
            }

            encrypt_error = olm_sys::olm_encrypt(
                self.olm_session_ptr,
                plaintext_buf.as_ptr() as *const _,
                plaintext_len,
                random_buf.as_mut_ptr() as *mut _,
                random_len,
                message_ptr,
                message_len,
            );

            mem::forget(message_buf);

            message_result =
                String::from_raw_parts(message_ptr as *mut u8, message_len, message_len);
        }

        if encrypt_error == errors::olm_error() {
            match Self::last_error(self.olm_session_ptr) {
                OlmSessionError::NotEnoughRandom => {
                    panic!("Not enough random data supplied for successfull encryption!")
                }
                OlmSessionError::OutputBufferTooSmall => {
                    panic!("Output buffer for ciphertext is too small!")
                }
                _ => panic!("Unknown error encountered during encryption of a message!"),
            }
        }

        message_result
    }

    /// Decrypts a message using this session.
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
        &mut self,
        message_type: OlmMessageType,
        message: &mut str,
    ) -> Result<String, OlmSessionError> {
        let decrypt_error;
        let plaintext_result;
        let plaintext_result_len;

        unsafe {
            // get the usize value associated with the supplied message type
            let message_type_val = match message_type {
                OlmMessageType::PreKey => olm_sys::OLM_MESSAGE_TYPE_PRE_KEY,
                _ => olm_sys::OLM_MESSAGE_TYPE_MESSAGE,
            };

            let message_buf = message.as_bytes_mut();
            let message_len = message_buf.len();
            let message_ptr = message_buf.as_mut_ptr() as *mut _;

            let plaintext_max_len = olm_sys::olm_decrypt_max_plaintext_length(
                self.olm_session_ptr,
                message_type_val,
                message_ptr,
                message_len,
            );

            let mut plaintext_buf: Vec<u8> = vec![0; plaintext_max_len];
            let plaintext_ptr = plaintext_buf.as_mut_ptr() as *mut _;

            plaintext_result_len = olm_sys::olm_decrypt(
                self.olm_session_ptr,
                message_type_val,
                message_ptr,
                message_len,
                plaintext_ptr,
                plaintext_max_len,
            );

            decrypt_error = plaintext_result_len;

            mem::forget(plaintext_buf);

            plaintext_result = String::from_raw_parts(
                plaintext_ptr as *mut u8,
                plaintext_result_len,
                plaintext_result_len,
            );
        }

        if decrypt_error == errors::olm_error() {
            if Self::last_error(self.olm_session_ptr) == OlmSessionError::OutputBufferTooSmall {
                panic!("Output buffer for plaintext is too small when decrypting!");
            }
            Err(Self::last_error(self.olm_session_ptr))
        } else {
            Ok(plaintext_result)
        }
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
    pub fn encrypt_message_type(&mut self) -> OlmMessageType {
        let message_type_result;
        let message_type_error;

        unsafe {
            message_type_result = olm_sys::olm_encrypt_message_type(self.olm_session_ptr);
        }

        // returns either result or error
        message_type_error = message_type_result;

        if message_type_error == errors::olm_error() {
            panic!("Unknown error encoutered, when getting the next encrypted message type from an OlmSession!");
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
    pub fn has_received_message(&mut self) -> bool {
        let received_message;

        unsafe {
            received_message = olm_sys::olm_session_has_received_message(self.olm_session_ptr)
        }

        // to get the bool value of an int_c type, check for inequality with zero
        received_message != 0
    }
}

/// The message types that are returned after encryption.
#[derive(Debug, PartialEq)]
pub enum OlmMessageType {
    PreKey,
    Message,
}

impl Drop for OlmSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_session(self.olm_session_ptr);
        }
    }
}
