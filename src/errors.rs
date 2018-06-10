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

use olm_sys;

pub fn olm_error() -> usize {
    let result;
    unsafe {
        result = olm_sys::olm_error();
    }
    result
}

/// All errors that could be caused by an operation regarding an OlmAccount.
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmAccountError {
    BadAccountKey,
    BadMessageKeyId,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    Unknown,
}

pub enum OlmUtilityError {
    InvalidBase64,
    OutputBufferTooSmall,
    BadMessageMac,
    Unknown,
}
