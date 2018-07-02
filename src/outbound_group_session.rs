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

use errors;
use errors::OlmGroupSessionError;
use olm_sys;
use ring::rand::{SecureRandom, SystemRandom};
use std::ffi::CStr;
use std::mem;

pub struct OlmOutboundGroupSession {
    _group_session_buf: Vec<u8>,
    pub group_session_ptr: *mut olm_sys::OlmOutboundGroupSession,
}

impl OlmOutboundGroupSession {
    pub fn new() -> Self {
        let olm_outbound_group_session_ptr;
        let mut olm_outbound_group_session_buf: Vec<u8>;
        let create_error;

        unsafe {
            olm_outbound_group_session_buf = vec![0; olm_sys::olm_outbound_group_session_size()];
            olm_outbound_group_session_ptr = olm_sys::olm_outbound_group_session(
                olm_outbound_group_session_buf.as_mut_ptr() as *mut _,
            );

            let random_len = olm_sys::olm_init_outbound_group_session_random_length(
                olm_outbound_group_session_ptr,
            );
            let mut random_buf: Vec<u8> = vec![0; random_len];
            {
                let rng = SystemRandom::new();
                rng.fill(random_buf.as_mut_slice()).unwrap();
            }
            let random_ptr = random_buf.as_mut_ptr() as *mut _;

            create_error = olm_sys::olm_init_outbound_group_session(
                olm_outbound_group_session_ptr,
                random_ptr,
                random_len,
            );
        }

        if create_error == errors::olm_error() {
            match Self::last_error(olm_outbound_group_session_ptr) {
                OlmGroupSessionError::OutputBufferTooSmall => panic!("The supplied buffer for the creation of OlmOutboundGroupSession was too small!"),
                _ => panic!("An unknown error occurred during the creating of OlmOutboundGroupSession!"),
            }
        }

        OlmOutboundGroupSession {
            _group_session_buf: olm_outbound_group_session_buf,
            group_session_ptr: olm_outbound_group_session_ptr,
        }
    }

    pub fn pickle(&self, key: &[u8]) -> String {
        let pickled_result;
        let pickle_error;

        unsafe {
            let mut pickled_buf =
                vec![0; olm_sys::olm_pickle_outbound_group_session_length(self.group_session_ptr)];
            let pickled_len = pickled_buf.len();
            let pickled_ptr = pickled_buf.as_mut_ptr() as *mut _;

            pickle_error = olm_sys::olm_pickle_outbound_group_session(
                self.group_session_ptr,
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

    pub fn unpickle(pickled: &str, key: &[u8]) -> Result<Self, OlmGroupSessionError> {
        let olm_outbound_group_session_ptr;
        let mut olm_outbound_group_session_buf: Vec<u8>;
        let unpickle_error;
        let mut pickled_cloned = pickled.clone().to_owned();

        unsafe {
            let pickled_len = pickled.len();
            let pickled_buf = pickled_cloned.as_bytes_mut();

            olm_outbound_group_session_buf = vec![0; olm_sys::olm_outbound_group_session_size()];
            olm_outbound_group_session_ptr = olm_sys::olm_outbound_group_session(
                olm_outbound_group_session_buf.as_mut_ptr() as *mut _,
            );

            unpickle_error = olm_sys::olm_unpickle_outbound_group_session(
                olm_outbound_group_session_ptr,
                key.as_ptr() as *const _,
                key.len(),
                pickled_buf.as_mut_ptr() as *mut _,
                pickled_len,
            );
        }

        if unpickle_error == errors::olm_error() {
            Err(Self::last_error(olm_outbound_group_session_ptr))
        } else {
            Ok(OlmOutboundGroupSession {
                _group_session_buf: olm_outbound_group_session_buf,
                group_session_ptr: olm_outbound_group_session_ptr,
            })
        }
    }

    fn last_error(
        group_session_ptr: *const olm_sys::OlmOutboundGroupSession,
    ) -> OlmGroupSessionError {
        let error;
        unsafe {
            let error_raw = olm_sys::olm_outbound_group_session_last_error(group_session_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

        match error {
            "BAD_ACCOUNT_KEY" => OlmGroupSessionError::BadAccountKey,
            "INVALID_BASE64" => OlmGroupSessionError::InvalidBase64,
            "NOT_ENOUGH_RANDOM" => OlmGroupSessionError::NotEnoughRandom,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmGroupSessionError::OutputBufferTooSmall,
            _ => OlmGroupSessionError::Unknown,
        }
    }

    pub fn encrypt(&self, mut plaintext: String) -> String {
        let message_result;
        let message_len;

        unsafe {
            let plaintext_buf = plaintext.as_bytes_mut();
            let plaintext_len = plaintext_buf.len();
            let plaintext_ptr = plaintext_buf.as_mut_ptr() as *mut u8;
            let message_max_len =
                olm_sys::olm_group_encrypt_message_length(self.group_session_ptr, plaintext_len);
            let message_buf: Vec<u8> = vec![0; message_max_len];
            let message_ptr = message_buf.as_ptr() as *mut u8;

            message_len = olm_sys::olm_group_encrypt(
                self.group_session_ptr,
                plaintext_ptr,
                plaintext_len,
                message_ptr,
                message_max_len,
            );

            mem::forget(message_buf);

            message_result = String::from_raw_parts(message_ptr, message_len, message_len);
        }

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

    pub fn session_message_index(&self) -> u32 {
        unsafe { olm_sys::olm_outbound_group_session_message_index(self.group_session_ptr) }
    }

    pub fn session_id(&self) -> String {
        let id_len;
        let id_result;

        unsafe {
            let id_max_len = olm_sys::olm_outbound_group_session_id_length(self.group_session_ptr);
            let mut id_buf: Vec<u8> = vec![0; id_max_len];
            let id_ptr = id_buf.as_mut_ptr() as *mut u8;

            id_len =
                olm_sys::olm_outbound_group_session_id(self.group_session_ptr, id_ptr, id_max_len);

            mem::forget(id_buf);

            id_result = String::from_raw_parts(id_ptr, id_len, id_len);
        }

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

    pub fn session_key(&self) -> String {
        let key_len;
        let key_result;

        unsafe {
            let key_max_len =
                olm_sys::olm_outbound_group_session_key_length(self.group_session_ptr);
            let mut key_buf: Vec<u8> = vec![0; key_max_len];
            let key_ptr = key_buf.as_mut_ptr() as *mut u8;

            key_len = olm_sys::olm_outbound_group_session_key(
                self.group_session_ptr,
                key_ptr,
                key_max_len,
            );

            mem::forget(key_buf);

            key_result = String::from_raw_parts(key_ptr, key_len, key_len);
        }

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

impl Drop for OlmOutboundGroupSession {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_outbound_group_session(self.group_session_ptr);
        }
    }
}
