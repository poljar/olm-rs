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

//! A collection of all errors that can be returned by `libolm`.
//!
//! All error enums additionally contain an error named `Unknown`,
//! for returning an error, in case an error is encountered by `libolm`,
//! but no error code is provided.

use olm_sys;
use std::fmt::Debug;

/// Since libolm does not do heap allocation and instead relies on the user to
/// provide already allocated buffers, a lot of potential errors regarding
/// buffer size can be encountered.
/// In most places in this library we create such buffers exactly the way
/// libolm would want, and as such a lot of potential errors would be eliminated.
/// If such an error is still encountered, it would indicate that something else
/// is seriously wrong with the execution environment, so we panic unrecoverably.
pub(crate) fn handle_fatal_error<E>(error: E)
where
    E: Debug,
{
    unreachable!("Encountered fatal error: {:?}", error);
}

pub(crate) fn olm_error() -> usize {
    unsafe { olm_sys::olm_error() }
}

/// All errors that could be caused by an operation regarding an `OlmAccount`.
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

/// All errors that could be caused by an operation regarding `OlmUitlity`.
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmUtilityError {
    InvalidBase64,
    OutputBufferTooSmall,
    BadMessageMac,
    Unknown,
}

/// All errors that could be caused by an operation regarding an `OlmSession`.
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmSessionError {
    BadAccountKey,
    BadMessageFormat,
    BadMessageKeyId,
    BadMessageMac,
    BadMessageVersion,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    Unknown,
}

/// All errors that could be caused by an operation regarding
/// `OlmOutboundGroupSession` and `OlmInboundGroupSession`.
/// Errors are named exactly like the ones in libolm.
#[derive(Debug, PartialEq)]
pub enum OlmGroupSessionError {
    BadAccountKey,
    BadMessageFormat,
    BadMessageMac,
    BadMessageVersion,
    BadSessionKey,
    InvalidBase64,
    NotEnoughRandom,
    OutputBufferTooSmall,
    UnknownMessageIndex,
    Unknown,
}
