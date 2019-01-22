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

//! This module wraps around all functions in `outbound_group_session.h`.

use crate::errors;
use crate::errors::OlmGroupSessionError;
use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;

/// An out-bound group session is responsible for encrypting outgoing
/// communication in a Megolm session.
pub struct OlmOutboundGroupSession {
    pub group_session_ptr: *mut olm_sys::OlmOutboundGroupSession,
}

impl OlmOutboundGroupSession {
    /// Creates a new instance of `OlmOutboundGroupSession`.
    ///
    /// # C-API equivalent
    /// `olm_init_outbound_group_session`
    ///
    /// # Panics
    /// * `NotEnoughRandom` for `OlmOutboundGroupSession`'s creation
    ///
    pub fn new() -> Self {
        let olm_outbound_group_session_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_outbound_group_session_size() }];
        let olm_outbound_group_session_buf_ptr =
            Box::into_raw(olm_outbound_group_session_buf.into_boxed_slice()) as *mut _;

        let olm_outbound_group_session_ptr =
            unsafe { olm_sys::olm_outbound_group_session(olm_outbound_group_session_buf_ptr) };

        let random_len = unsafe {
            olm_sys::olm_init_outbound_group_session_random_length(olm_outbound_group_session_ptr)
        };
        let mut random_buf: Vec<u8> = vec![0; random_len];
        {
            let rng = SystemRandom::new();
            rng.fill(random_buf.as_mut_slice()).unwrap();
        }
        let random_ptr = Box::into_raw(random_buf.into_boxed_slice());

        let create_error = unsafe {
            olm_sys::olm_init_outbound_group_session(
                olm_outbound_group_session_ptr,
                random_ptr as *mut _,
                random_len,
            )
        };

        unsafe { Box::from_raw(random_ptr) };

        if create_error == errors::olm_error() {
            match Self::last_error(olm_outbound_group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => panic!("The supplied buffer for the creation of OlmOutboundGroupSession was too small!"),
                _ => panic!("An unknown error occurred during the creating of OlmOutboundGroupSession!"),
            }
        }

        OlmOutboundGroupSession {
            group_session_ptr: olm_outbound_group_session_ptr,
        }
    }

    /// Serialises an `OlmOutboundGroupSession` to encrypted Base64. The encryption key is free to choose
    /// (empty byte slice is allowed).
    ///
    /// # C-API equivalent
    /// `olm_pickle_outbound_group_session`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for `OlmOutboundGroupSession`'s pickled buffer
    ///
    pub fn pickle(&self, key: &[u8]) -> String {
        let pickled_len =
            unsafe { olm_sys::olm_pickle_outbound_group_session_length(self.group_session_ptr) };
        let pickled_buf = vec![0; pickled_len];

        let pickled_ptr = Box::into_raw(pickled_buf.into_boxed_slice());

        let pickle_error = unsafe {
            olm_sys::olm_pickle_outbound_group_session(
                self.group_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_ptr as *mut _,
                pickled_len,
            )
        };

        let pickled_after = unsafe { Box::from_raw(pickled_ptr) };

        let pickled_result = String::from_utf8(pickled_after.to_vec())
            .expect("Pickled OlmOutboundGroupSession isn't valid UTF-8");

        if pickle_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => {
                    panic!("Buffer for pickled OlmOutboundGroupSession is too small!")
                }
                _ => panic!("Unknown error occurred while pickling OlmOutboundGroupSession!"),
            }
        } else {
            pickled_result
        }
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an `OlmOutboundGroupSession`.
    ///
    /// # C-API equivalent
    /// `olm_unpickle_outbound_group_session`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the session was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, key: &[u8]) -> Result<Self, OlmGroupSessionError> {
        let pickled_len = pickled.len();
        let pickled_buf = unsafe { pickled.as_bytes_mut() };

        let olm_outbound_group_session_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_outbound_group_session_size() }];
        let olm_outbound_group_session_buf_ptr =
            Box::into_raw(olm_outbound_group_session_buf.into_boxed_slice());

        let olm_outbound_group_session_ptr = unsafe {
            olm_sys::olm_outbound_group_session(olm_outbound_group_session_buf_ptr as *mut _)
        };

        let unpickle_error = unsafe {
            olm_sys::olm_unpickle_outbound_group_session(
                olm_outbound_group_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            )
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_outbound_group_session_ptr))
        } else {
            Ok(OlmOutboundGroupSession {
                group_session_ptr: olm_outbound_group_session_ptr,
            })
        }
    }

    /// Returns the last error that occurred for an `OlmOutboundSession`.
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmGroupSessionError::Unknown is returned on an unknown error code.
    fn last_error(
        group_session_ptr: *const olm_sys::OlmOutboundGroupSession,
    ) -> OlmGroupSessionError {
        let error_raw =
            unsafe { olm_sys::olm_outbound_group_session_last_error(group_session_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_ACCOUNT_KEY" => OlmGroupSessionError::BadAccountKey,
            "INVALID_BASE64" => OlmGroupSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmGroupSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmGroupSessionError::OutputBufferTooSmall,
            _ => OlmGroupSessionError::Unknown,
        }
    }

    /// Encrypts a plaintext message using the session.
    ///
    /// # C-API equivalent
    /// * `olm_group_encrypt`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for encrypted message
    ///
    pub fn encrypt(&self, mut plaintext: String) -> String {
        let plaintext_buf = unsafe { plaintext.as_bytes_mut() };
        let plaintext_len = plaintext_buf.len();
        let plaintext_ptr = plaintext_buf.as_mut_ptr() as *mut _;
        let message_max_len = unsafe {
            olm_sys::olm_group_encrypt_message_length(self.group_session_ptr, plaintext_len)
        };
        let message_buf: Vec<u8> = vec![0; message_max_len];
        let message_ptr = Box::into_raw(message_buf.into_boxed_slice());

        let message_len = unsafe {
            olm_sys::olm_group_encrypt(
                self.group_session_ptr,
                plaintext_ptr,
                plaintext_len,
                message_ptr as *mut _,
                message_max_len,
            )
        };

        let message_after = unsafe { Box::from_raw(message_ptr) };
        let message_result = String::from_utf8(message_after[0..message_len].to_vec())
            .expect("Encrypted message by OlmOutboundGroupSession isn't valid UTF-8");

        // Can return both final message length or an error code
        let encrypt_error = message_len;
        if encrypt_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => {
                    panic!("Output buffer for encrypted data was to small!")
                }
                _ => panic!(
                    "An unkown error occurred when encrypting using OlmOutboundGroupSession!"
                ),
            }
        }

        message_result
    }

    /// Get the current message index for this session.
    ///
    /// Each message is sent with an increasing index; this returns the index for the next message.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_message_index`
    ///
    pub fn session_message_index(&self) -> u32 {
        unsafe { olm_sys::olm_outbound_group_session_message_index(self.group_session_ptr) }
    }

    /// Get a base64-encoded identifier for this session.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_id`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for too small ID buffer
    ///
    pub fn session_id(&self) -> String {
        let id_max_len =
            unsafe { olm_sys::olm_outbound_group_session_id_length(self.group_session_ptr) };
        let id_buf: Vec<u8> = vec![0; id_max_len];
        let id_ptr = Box::into_raw(id_buf.into_boxed_slice());

        let id_len = unsafe {
            olm_sys::olm_outbound_group_session_id(
                self.group_session_ptr as *mut _,
                id_ptr as *mut _,
                id_max_len,
            )
        };

        let id_after = unsafe { Box::from_raw(id_ptr) };
        let id_result = String::from_utf8(id_after.to_vec())
            .expect("OutboundGroupSession's session ID isn't valid UTF-8");

        // Can return both session id length or an error code
        let id_error = id_len;
        if id_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => {
                    panic!("Output buffer for OlmOutboundGroupSession's ID was to small!")
                }
                _ => panic!("An unkown error occurred when getting OlmOutboundGroupSession's ID!"),
            }
        }

        id_result
    }

    /// Get the base64-encoded current ratchet key for this session.
    ///
    /// Each message is sent with a different ratchet key. This function returns the
    /// ratchet key that will be used for the next message.
    ///
    /// # C-API equivalent
    /// * `olm_outbound_group_session_key`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for too small session key buffer
    ///
    pub fn session_key(&self) -> String {
        let key_max_len =
            unsafe { olm_sys::olm_outbound_group_session_key_length(self.group_session_ptr) };
        let key_buf: Vec<u8> = vec![0; key_max_len];
        let key_ptr = Box::into_raw(key_buf.into_boxed_slice());

        let key_len = unsafe {
            olm_sys::olm_outbound_group_session_key(
                self.group_session_ptr,
                key_ptr as *mut _,
                key_max_len,
            )
        };

        let key_after = unsafe { Box::from_raw(key_ptr) };
        let key_result = String::from_utf8(key_after.to_vec())
            .expect("OutboundGroupSession's session key isn't valid UTF-8");

        // Can return both session id length or an error code
        let key_error = key_len;
        if key_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => {
                    panic!("Output buffer for OlmOutboundGroupSession's key was to small!")
                }
                _ => panic!("An unkown error occurred when getting OlmOutboundGroupSession's key!"),
            }
        }

        key_result
    }
}

impl Default for OlmOutboundGroupSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmOutboundGroupSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_outbound_group_session(self.group_session_ptr);
            Box::from_raw(self.group_session_ptr);
        }
    }
}
