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
    _olm_utility_buf: Vec<u8>,
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
        let olm_utility_ptr;
        let mut olm_utility_buf: Vec<u8>;
        unsafe {
            // allocate the buffer for OlmUtility to be written into
            olm_utility_buf = vec![0; olm_sys::olm_utility_size()];
            olm_utility_ptr = olm_sys::olm_utility(olm_utility_buf.as_mut_ptr() as *mut _);
        }

        Self {
            _olm_utility_buf: olm_utility_buf,
            olm_utility_ptr: olm_utility_ptr,
        }
    }

    /// Returns the last error that occurred for an OlmUtility
    /// Since error codes are encoded as CStrings by libolm,
    /// OlmUtilityError::Unknown is returned on an unknown error code.
    fn last_error(olm_utility_ptr: *mut olm_sys::OlmUtility) -> OlmUtilityError {
        let error;
        unsafe {
            let error_raw = olm_sys::olm_utility_last_error(olm_utility_ptr);
            error = CStr::from_ptr(error_raw).to_str().unwrap();
        }

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
    pub fn sha256_bytes(&self, input_buf: &mut [u8]) -> String {
        let sha256_result;
        let sha256_error;
        unsafe {
            let input_ptr = input_buf.as_mut_ptr() as *mut _;
            let output_len = olm_sys::olm_sha256_length(self.olm_utility_ptr);
            let mut output_buf = vec![0; output_len];
            let output_ptr = output_buf.as_mut_ptr() as *mut _;

            sha256_error = olm_sys::olm_sha256(
                self.olm_utility_ptr,
                input_ptr,
                input_buf.len(),
                output_ptr,
                output_len,
            );

            mem::forget(output_buf);

            sha256_result = String::from_raw_parts(output_ptr as *mut u8, output_len, output_len)
        }

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
    pub fn sha256_utf8_msg(&self, msg: &mut str) -> String {
        unsafe { self.sha256_bytes(msg.as_bytes_mut()) }
    }

    /// Verify a ed25519 signature.
    ///
    /// # C-API equivalent
    /// `olm_ed25519_verify`
    ///
    pub fn ed25519_verify_bytes(
        &self,
        key: &mut str,
        data_buf: &mut [u8],
        signature: &mut str,
    ) -> Result<bool, OlmUtilityError> {
        let ed25519_verify_result: usize;
        let ed25519_verify_error: usize;

        unsafe {
            let key_buf = key.as_bytes_mut();
            let signature_buf = signature.as_bytes_mut();

            let key_ptr = key_buf.as_mut_ptr() as *mut _;
            let data_ptr = data_buf.as_mut_ptr() as *mut _;
            let signature_ptr = signature_buf.as_mut_ptr() as *mut _;

            ed25519_verify_error = olm_sys::olm_ed25519_verify(
                self.olm_utility_ptr,
                key_ptr,
                key_buf.len(),
                data_ptr,
                data_buf.len(),
                signature_ptr,
                signature_buf.len(),
            );

            // Since the two values are the same it is safe to clone
            ed25519_verify_result = ed25519_verify_error.clone();
        }

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
        key: &mut str,
        message: &mut str,
        signature: &mut str,
    ) -> Result<bool, OlmUtilityError> {
        unsafe { self.ed25519_verify_bytes(key, message.as_bytes_mut(), signature) }
    }
}

impl Drop for OlmUtility {
    fn drop(&mut self) {
        unsafe {
            olm_sys::olm_clear_utility(self.olm_utility_ptr);
        }
    }
}
