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
// along with this program.  If not, see <https://www.gnu.org/licenses/>

//! This module wraps around all functions in `inbound_group_session.h`.

use crate::errors;
use crate::errors::OlmGroupSessionError;
use olm_sys;
use std::ffi::CStr;

/// An in-bound group session is responsible for decrypting incoming
/// communication in a Megolm session.
pub struct OlmInboundGroupSession {
    pub group_session_ptr: *mut olm_sys::OlmInboundGroupSession,
}

impl OlmInboundGroupSession {
    /// Creates a new instance of `OlmInboundGroupSession`.
    ///
    /// # C-API equivalent
    /// `olm_init_inbound_group_session`
    ///
    /// # Errors
    /// * `InvalidBase64` if session key is invalid base64
    /// * `BadSessionKey` if session key is invalid
    ///
    pub fn new(key: &str) -> Result<Self, OlmGroupSessionError> {
        let olm_inbound_group_session_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_inbound_group_session_size() }];
        let olm_inbound_group_session_buf_ptr =
            Box::into_raw(olm_inbound_group_session_buf.into_boxed_slice()) as *mut _;

        let olm_inbound_group_session_ptr =
            unsafe { olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf_ptr) };
        let key_buf = key.as_bytes();

        let create_error = unsafe {
            olm_sys::olm_init_inbound_group_session(
                olm_inbound_group_session_ptr as *mut _,
                key_buf.as_ptr(),
                key_buf.len(),
            )
        };

        if create_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
            })
        }
    }

    /// Import an inbound group session, from a previous export.
    ///
    /// # C-API equivalent
    /// `olm_import_inbound_group_session`
    ///
    /// # Errors
    /// * `InvalidBase64` if session key is invalid base64
    /// * `BadSessionKey` if session key is invalid
    ///
    pub fn import(key: &str) -> Result<Self, OlmGroupSessionError> {
        let olm_inbound_group_session_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_inbound_group_session_size() }];
        let olm_inbound_group_session_buf_ptr =
            Box::into_raw(olm_inbound_group_session_buf.into_boxed_slice()) as *mut _;

        let olm_inbound_group_session_ptr =
            unsafe { olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf_ptr) };

        let key_buf = key.as_bytes();
        let key_ptr = key_buf.as_ptr() as *const _;

        let import_error = unsafe {
            olm_sys::olm_import_inbound_group_session(
                olm_inbound_group_session_ptr,
                key_ptr,
                key_buf.len(),
            )
        };

        if import_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
            })
        }
    }

    /// Serialises an `OlmInboundGroupSession` to encrypted Base64. The encryption key is free to choose
    /// (empty byte slice is allowed).
    ///
    /// # C-API equivalent
    /// `olm_pickle_inbound_group_session`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for `OlmInboundGroupSession`'s pickled buffer
    ///
    pub fn pickle(&self, key: &[u8]) -> String {
        let pickled_buf =
            vec![
                0;
                unsafe { olm_sys::olm_pickle_inbound_group_session_length(self.group_session_ptr) }
            ];
        let pickled_len = pickled_buf.len();
        let pickled_ptr = Box::into_raw(pickled_buf.into_boxed_slice());

        let pickle_error = unsafe {
            olm_sys::olm_pickle_inbound_group_session(
                self.group_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_ptr as *mut _,
                pickled_len,
            )
        };

        let pickled_after: Box<[u8]> = unsafe { Box::from_raw(pickled_ptr) };
        let pickled_result = String::from_utf8(pickled_after.to_vec())
            .expect("Pickled InboundGroupSession isn't valid UTF-8");

        if pickle_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => {
                    panic!("Buffer for pickled OlmInboundGroupSession is too small!")
                }
                _ => panic!("Unknown error occurred while pickling OlmInboundGroupSession!"),
            }
        } else {
            pickled_result
        }
    }

    /// Deserialises from encrypted Base64 that was previously obtained by pickling an `OlmInboundGroupSession`.
    ///
    /// # C-API equivalent
    /// `olm_unpickle_inbound_group_session`
    ///
    /// # Errors
    /// * `BadAccountKey` if the key doesn't match the one the session was encrypted with
    /// * `InvalidBase64` if decoding the supplied `pickled` string slice fails
    ///
    pub fn unpickle(mut pickled: String, key: &[u8]) -> Result<Self, OlmGroupSessionError> {
        let pickled_len = pickled.len();
        let pickled_buf = unsafe { pickled.as_bytes_mut() };

        let olm_inbound_group_session_buf: Vec<u8> =
            vec![0; unsafe { olm_sys::olm_inbound_group_session_size() }];
        let olm_inbound_group_session_buf_ptr =
            Box::into_raw(olm_inbound_group_session_buf.into_boxed_slice()) as *mut _;
        let olm_inbound_group_session_ptr =
            unsafe { olm_sys::olm_inbound_group_session(olm_inbound_group_session_buf_ptr) };

        let unpickle_error = unsafe {
            olm_sys::olm_unpickle_inbound_group_session(
                olm_inbound_group_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            )
        };

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_inbound_group_session_ptr))
        } else {
            Ok(OlmInboundGroupSession {
                group_session_ptr: olm_inbound_group_session_ptr,
            })
        }
    }

    /// Returns the last error that occurred for an `OlmInboundSession`.
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmGroupSessionError::Unknown is returned on an unknown error code.
    fn last_error(
        group_session_ptr: *const olm_sys::OlmInboundGroupSession,
    ) -> OlmGroupSessionError {
        let error_raw = unsafe { olm_sys::olm_inbound_group_session_last_error(group_session_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_ACCOUNT_KEY" => OlmGroupSessionError::BadAccountKey,
            "BAD_MESSAGE_FORMAT" => OlmGroupSessionError::BadMessageFormat,
            "BAD_MESSAGE_MAC" => OlmGroupSessionError::BadMessageMac,
            "BAD_MESSAGE_VERSION" => OlmGroupSessionError::BadMessageVersion,
            "BAD_SESSION_KEY" => OlmGroupSessionError::BadSessionKey,
            "INVALID_BASE64" => OlmGroupSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmGroupSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmGroupSessionError::OutputBufferTooSmall,
            "UNKNOWN_MESSAGE_INDEX" => OlmGroupSessionError::UnknownMessageIndex,
            _ => OlmGroupSessionError::Unknown,
        }
    }

    /// Decrypts ciphertext received for this group session.
    ///
    /// Returns both plaintext and message index.
    ///
    /// # C-API equivalent
    /// * `olm_group_decrypt`
    ///
    /// # Errors
    /// * `InvalidBase64` if the message is invalid base64
    /// * `BadMessageVersion` if the message was encrypted with an unsupported version of the protocol
    /// * `BadMessageFormat` if the message headers could not be decoded
    /// * `BadMessageMac` if the message could not be verified
    /// * `UnknownMessageIndex` if we do not have a session key corresponding to the message's index
    /// (ie, it was sent before the session key was shared with us)
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for decrypted ciphertext
    ///
    pub fn decrypt(&self, mut message: String) -> Result<(String, u32), OlmGroupSessionError> {
        // This is for capturing the output of olm_group_decrypt
        let message_index = 0;

        // We need to clone the message because
        // olm_decrypt_max_plaintext_length destroys the input buffer
        let mut message_for_len = message.clone();
        let message_buf = unsafe { message_for_len.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;

        let plaintext_buf: Vec<u8> = vec![
            0;
            unsafe {
                olm_sys::olm_group_decrypt_max_plaintext_length(
                    self.group_session_ptr,
                    message_ptr,
                    message_len,
                )
            }
        ];
        let message_buf = unsafe { message.as_bytes_mut() };
        let message_len = message_buf.len();
        let message_ptr = message_buf.as_mut_ptr() as *mut _;
        let plaintext_max_len = plaintext_buf.len();
        let plaintext_ptr = Box::into_raw(plaintext_buf.into_boxed_slice());

        let plaintext_len = unsafe {
            olm_sys::olm_group_decrypt(
                self.group_session_ptr,
                message_ptr,
                message_len,
                plaintext_ptr as *mut _,
                plaintext_max_len,
                message_index as *mut _,
            )
        };

        // Error code or plaintext length is returned
        let decrypt_error = plaintext_len;

        if decrypt_error == errors::olm_error() {
            let error_code = Self::last_error(self.group_session_ptr);

            if error_code == OlmGroupSessionError::OutputBufferTooSmall {
                panic!("Output buffer for decrypting ciphertext from group session too small!");
            }

            return Err(error_code);
        }

        let plaintext_after = unsafe { Box::from_raw(plaintext_ptr) };
        let plaintext = String::from_utf8(plaintext_after[0..plaintext_len].to_vec())
            .expect("Decrypted plaintext for InboundGroupSession isn't valid UTF-8");
        Ok((plaintext, message_index))
    }

    /// Export the base64-encoded ratchet key for this session, at the given index,
    /// in a format which can be used by import
    ///
    /// # C-API equivalent
    /// * `olm_export_inbound_group_session`
    ///
    /// # Errors
    /// * `UnkownMessageIndex` if we do not have a session key corresponding to the given index
    /// (ie, it was sent before the session key was shared with us)
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for export buffer
    ///
    pub fn export(&self, message_index: u32) -> Result<String, OlmGroupSessionError> {
        let key_len =
            unsafe { olm_sys::olm_export_inbound_group_session_length(self.group_session_ptr) };
        let key_buf: Vec<u8> = vec![0; key_len];
        let key_ptr = Box::into_raw(key_buf.into_boxed_slice());

        let export_error = unsafe {
            olm_sys::olm_export_inbound_group_session(
                self.group_session_ptr,
                key_ptr as *mut _,
                key_len,
                message_index,
            )
        };

        let key_after = unsafe { Box::from_raw(key_ptr) };
        let export_result = String::from_utf8(key_after.to_vec())
            .expect("InboundGroupSession's export isn't valid UTF-8");

        if export_error == errors::olm_error() {
            let error_code = Self::last_error(self.group_session_ptr);
            if error_code == OlmGroupSessionError::OutputBufferTooSmall {
                panic!("Output buffer was too small when exporting an OlmInboundGroupSession!");
            }

            Err(error_code)
        } else {
            Ok(export_result)
        }
    }

    /// Get the first message index we know how to decrypt.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_first_known_index`
    ///
    pub fn first_known_index(&self) -> u32 {
        unsafe { olm_sys::olm_inbound_group_session_first_known_index(self.group_session_ptr) }
    }

    /// Get a base64-encoded identifier for this session.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_id`
    ///
    /// # Panics
    /// * `OutputBufferTooSmall` for session ID buffer
    ///
    pub fn session_id(&self) -> String {
        let session_id_len =
            unsafe { olm_sys::olm_inbound_group_session_id_length(self.group_session_ptr) };
        let session_id_buf: Vec<u8> = vec![0; session_id_len];
        let session_id_ptr = Box::into_raw(session_id_buf.into_boxed_slice());

        let session_id_error = unsafe {
            olm_sys::olm_inbound_group_session_id(
                self.group_session_ptr,
                session_id_ptr as *mut _,
                session_id_len,
            )
        };

        let session_id_after = unsafe { Box::from_raw(session_id_ptr) };
        let session_id_result = String::from_utf8(session_id_after.to_vec())
            .expect("InboundGroupSession's session ID isn't valid UTF-8");

        if session_id_error == errors::olm_error() {
            match Self::last_error(self.group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => panic!(
                    "The output buffer for the InboundGroupSession's session ID was too small!"
                ),
                _ => panic!(
                    "Unknown error encountered when getting the InboundGroupSession's session ID!"
                ),
            }
        }

        session_id_result
    }

    /// Check if the session has been verified as a valid session.
    ///
    /// (A session is verified either because the original session share was signed,
    /// or because we have subsequently successfully decrypted a message.)
    ///
    /// This is mainly intended for the unit tests (in libolm), currently.
    ///
    /// # C-API equivalent
    /// * `olm_inbound_group_session_is_verified`
    pub fn session_is_verified(&self) -> bool {
        0 == unsafe { olm_sys::olm_inbound_group_session_is_verified(self.group_session_ptr) }
    }
}

impl Drop for OlmInboundGroupSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_inbound_group_session(self.group_session_ptr);
            Box::from_raw(self.group_session_ptr);
        }
    }
}
