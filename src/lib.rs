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

//! This is a wrapper for [`libolm`](https://git.matrix.org/git/olm/about/).
//! It exposes all original functionality, split into task oriented modules.
//!
//! This wrapper takes care of memory allocation for you, so all functions
//! in the original library exposing the buffer length of certain read/write
//! buffers (and similar functionality) are not included in this wrapper,
//! because they are used internally.
//!
//! Random number generation is also handled internally and hence there are no
//! function arguments for supplying random data.
//!
//! All errors from `libolm` that are encountered result in a panic,
//! because they are unrecoverably fatal.
//! In case a function can panic, it is annotated as such in the documentation.
//! Panics should technically never happen however.
extern crate olm_sys;
extern crate ring;

pub mod account;
pub mod errors;
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
        major: major,
        minor: minor,
        patch: patch,
    }
}
