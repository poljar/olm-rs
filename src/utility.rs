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

use errors;
use errors::OlmUtilityError;
use olm_sys;
use std::ffi::CStr;
use std::mem;

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
        let mut olm_utility_buf: Vec<u8> = vec![0; unsafe { olm_sys::olm_utility_size() }];
        let olm_utility_buf_ptr = olm_utility_buf.as_mut_ptr() as *mut _;
        mem::forget(olm_utility_buf);

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
        let mut output_buf = vec![0; output_len];
        let output_ptr = output_buf.as_mut_ptr() as *mut _;

        let sha256_error = unsafe {
            olm_sys::olm_sha256(
                self.olm_utility_ptr,
                input_buf.as_ptr() as *const _,
                input_buf.len(),
                output_ptr,
                output_len,
            )
        };

        mem::forget(output_buf);

        let sha256_result =
            unsafe { String::from_raw_parts(output_ptr as *mut u8, output_len, output_len) };

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
    pub fn ed25519_verify_bytes(
        &self,
        key: &str,
        data_buf: &[u8],
        signature: &mut [u8],
    ) -> Result<bool, OlmUtilityError> {
        let ed25519_verify_error = unsafe {
            olm_sys::olm_ed25519_verify(
                self.olm_utility_ptr,
                key.as_ptr() as *const _,
                key.len(),
                data_buf.as_ptr() as *const _,
                data_buf.len(),
                signature.as_mut_ptr() as *mut _,
                signature.len(),
            )
        };

        // Since the two values are the same it is safe to copy
        let ed25519_verify_result = ed25519_verify_error;

        if ed25519_verify_error == errors::olm_error() {
            Err(Self::last_error(self.olm_utility_ptr))
        } else {
            match ed25519_verify_result {
                0 => Ok(true),
                _ => Ok(false),
            }
        }
    }

    /// Convenience function that converts the UTF-8 message
    /// to bytes and calls `ed25519_verify_bytes()`, returning its output
    pub fn ed25519_verify_utf8_msg(
        &self,
        key: &str,
        message: &str,
        signature: &str,
    ) -> Result<bool, OlmUtilityError> {
        let mut signature_cloned = signature.to_string();
        self.ed25519_verify_bytes(key, message.as_bytes(), unsafe {
            signature_cloned.as_bytes_mut()
        })
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
            mem::drop(Vec::from_raw_parts(
                self.olm_utility_ptr,
                0,
                olm_sys::olm_utility_size(),
            ));
        }
    }
}
