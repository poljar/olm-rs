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

//! This is a wrapper for [`libolm`](https://git.matrix.org/git/olm/about/).
//! It exposes all original functionality, split into task oriented modules.
//!
//! This wrapper takes care of memory allocation for you, so all functions
//! in the original library exposing the buffer length of certain read/write
//! buffers (and similar functionality) are not exposed by this wrapper.
//!
//! Random number generation is also handled internally and hence there are no
//! function arguments for supplying random data.
//!
//! All errors of the type `NOT_ENOUGH_RANDOM` and `OUTPUT_BUFFER_TOO_SMALL` from
//! `libolm` that are encountered result in a panic, as they are unrecoverably fatal.
//! Similarly the output from `libolm` is assumed to be trusted, except for encryption
//! functions. If the string output from any other function is not properly encoded
//! as UTF-8, a panic will occur as well.
//! In case a function can panic, it is annotated as such in the documentation.
//!
//! All panics can be considered unreachable, they are documented however for the
//! purpose of transparency.

pub mod account;
pub mod errors;
pub mod inbound_group_session;
pub mod outbound_group_session;
pub mod session;
pub mod utility;

/// Used for storing the version number of libolm.
/// Solely returned by [`get_library_version()`](fn.get_library_version.html).
#[derive(Debug, PartialEq)]
pub struct OlmVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

/// Used for setting the encryption parameter for pickling (serialisation) functions.
/// `Unencrypted` is functionally equivalent to `Encrypted{key: &[]}`, but is much more clear.
/// Pickling modes have to be equivalent for pickling and unpickling operations to succeed.
pub enum PicklingMode<'a> {
    Unencrypted,
    Encrypted { key: &'a [u8] },
}

/// Convenience function that maps `Unencrypted` to an empty slice, or
/// unwraps `Encrypted`. Mostly for reducing code duplication.
pub(crate) fn convert_pickling_mode_to_key(mode: PicklingMode) -> &[u8] {
    match mode {
        PicklingMode::Unencrypted => &[],
        PicklingMode::Encrypted { key: x } => x,
    }
}

/// Returns the version number of the currently utilised `libolm`.
///
/// # C-API equivalent
/// `olm_get_library_version`
pub fn get_library_version() -> OlmVersion {
    let mut major = 0;
    let mut minor = 0;
    let mut patch = 0;
    let major_ptr: *mut u8 = &mut major;
    let minor_ptr: *mut u8 = &mut minor;
    let patch_ptr: *mut u8 = &mut patch;

    unsafe {
        olm_sys::olm_get_library_version(major_ptr, minor_ptr, patch_ptr);
    }

    OlmVersion {
        major,
        minor,
        patch,
    }
}
