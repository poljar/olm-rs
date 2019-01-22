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

//! This module wraps around all functions following the pattern `olm_utility_*`.

use crate::errors;
use crate::errors::OlmUtilityError;
use olm_sys;
use std::ffi::CStr;

pub struct OlmUtility {
    olm_utility_ptr: *mut olm_sys::OlmUtility,
}

/// Allows you to make use of crytographic hashing via SHA-2 and
/// verifying ed25519 signatures.
impl OlmUtility {
    /// Creates a new instance of OlmUtility.
    ///
    /// # C-API equivalent
    /// `olm_utility`
    ///
    pub fn new() -> Self {
        // allocate the buffer for OlmUtility to be written into
        let olm_utility_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_utility_size() }];
        let olm_utility_buf_ptr = Box::into_raw(olm_utility_buf.into_boxed_slice()) as *mut _;

        let olm_utility_ptr = unsafe { olm_sys::olm_utility(olm_utility_buf_ptr) };

        Self { olm_utility_ptr }
    }

    /// Returns the last error that occurred for an OlmUtility
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmUtilityError::Unknown is returned on an unknown error code.
    fn last_error(olm_utility_ptr: *mut olm_sys::OlmUtility) -> OlmUtilityError {
        let error_raw = unsafe { olm_sys::olm_utility_last_error(olm_utility_ptr) };
        let error = unsafe { CStr::from_ptr(error_raw).to_str().unwrap() };

        match error {
            "BAD_MESSAGE_MAC" => OlmUtilityError::BadMessageMac,
            "OUTPUT_BUFFER_TOO_SMALL" => OlmUtilityError::OutputBufferTooSmall,
            "INVALID_BASE64" => OlmUtilityError::InvalidBase64,
            _ => OlmUtilityError::Unknown,
        }
    }

    /// Returns a sha256 of the supplied byte slice.
    ///
    /// # C-API equivalent
    /// `olm_sha256`
    ///
    /// # Panics
    /// * `OUTPUT_BUFFER_TOO_SMALL` for supplied output buffer
    ///
    pub fn sha256_bytes(&self, input_buf: &[u8]) -> String {
        let output_len = unsafe { olm_sys::olm_sha256_length(self.olm_utility_ptr) };
        let output_buf = vec![0; output_len];
        let output_ptr = Box::into_raw(output_buf.into_boxed_slice());

        let sha256_error = unsafe {
            olm_sys::olm_sha256(
                self.olm_utility_ptr,
                input_buf.as_ptr() as *const _,
                input_buf.len(),
                output_ptr as *mut _,
                output_len,
            )
        };

        let output_after = unsafe { Box::from_raw(output_ptr) };
        let sha256_result = String::from_utf8(output_after.to_vec())
            .expect("SHA256 that was genereated by OlmUtility isn't valid UTF-8");

        // Errors from sha256 are fatal
        if sha256_error == errors::olm_error() {
            match Self::last_error(self.olm_utility_ptr) {
                OlmUtilityError::OutputBufferTooSmall => panic!("Buffer for sha256 is too small!"),
                _ => panic!("Unknown error occured while creating sha256"),
            }
        }

        sha256_result
    }

    /// Convenience function that converts the UTF-8 message
    /// to bytes and then calls `sha256_bytes()`, returning its output.
    pub fn sha256_utf8_msg(&self, msg: &str) -> String {
        self.sha256_bytes(msg.as_bytes())
    }

    /// Verify a ed25519 signature.
    ///
    /// # C-API equivalent
    /// `olm_ed25519_verify`
    ///
    pub fn ed25519_verify(
        &self,
        key: &str,
        message: &str,
        signature: &mut str,
    ) -> Result<bool, OlmUtilityError> {
        let signature_bytes = unsafe { signature.as_bytes_mut() };
        let message_bytes = message.as_bytes();

        let ed25519_verify_error = unsafe {
            olm_sys::olm_ed25519_verify(
                self.olm_utility_ptr,
                key.as_ptr() as *const _,
                key.len(),
                message_bytes.as_ptr() as *const _,
                message_bytes.len(),
                signature_bytes.as_mut_ptr() as *mut _,
                signature_bytes.len(),
            )
        };

        // Since the two values are the same it is safe to copy
        let ed25519_verify_result: usize = ed25519_verify_error;

        if ed25519_verify_error == errors::olm_error() {
            Err(Self::last_error(self.olm_utility_ptr))
        } else {
            Ok(ed25519_verify_result == 0)
        }
    }
}

impl Default for OlmUtility {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OlmUtility {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_utility(self.olm_utility_ptr);
            Box::from_raw(self.olm_utility_ptr);
        }
    }
}
