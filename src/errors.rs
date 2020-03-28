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
use std::error::Error;
use std::fmt;
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

static BAD_ACCOUNT_KEY: &str = "The supplied account key is invalid";
static INVALID_BASE64: &str = "The input base64 was invalid";
static BAD_MSG_KEY_ID: &str = "The message references an unknown key id";
static BAD_MSG_FMT: &str = "The message couldn't be decoded";
static BAD_MSG_MAC: &str = "The message couldn't be decrypted";
static BAD_MSG_VERSION: &str = "The message version is unsupported";
static BAD_SESSION_KEY: &str = "Can't initialise the inbound group session, invalid session key";
static BAD_MSG_INDEX: &str =
    "Can't decode the message, message index is earlier than our earliest known session key";
static NOT_ENOUGH_RAND: &str = "Not enough entropy was supplied";
static BUFFER_SMALL: &str = "Supplied output buffer is too small";
static UNKNOWN: &str = "An unknown error occured.";

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

impl fmt::Display for OlmAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmAccountError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmAccountError::BadMessageKeyId => BAD_MSG_KEY_ID,
            OlmAccountError::InvalidBase64 => INVALID_BASE64,
            OlmAccountError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmAccountError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmAccountError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}

impl Error for OlmAccountError {}
impl Error for OlmSessionError {}
impl Error for OlmGroupSessionError {}

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

impl fmt::Display for OlmSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmSessionError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmSessionError::BadMessageKeyId => BAD_MSG_KEY_ID,
            OlmSessionError::BadMessageFormat => BAD_MSG_FMT,
            OlmSessionError::BadMessageMac => BAD_MSG_MAC,
            OlmSessionError::BadMessageVersion => BAD_MSG_VERSION,
            OlmSessionError::InvalidBase64 => INVALID_BASE64,
            OlmSessionError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmSessionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmSessionError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
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

impl fmt::Display for OlmGroupSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            OlmGroupSessionError::BadAccountKey => BAD_ACCOUNT_KEY,
            OlmGroupSessionError::BadSessionKey => BAD_SESSION_KEY,
            OlmGroupSessionError::UnknownMessageIndex => BAD_MSG_INDEX,
            OlmGroupSessionError::BadMessageFormat => BAD_MSG_FMT,
            OlmGroupSessionError::BadMessageMac => BAD_MSG_MAC,
            OlmGroupSessionError::BadMessageVersion => BAD_MSG_VERSION,
            OlmGroupSessionError::InvalidBase64 => INVALID_BASE64,
            OlmGroupSessionError::NotEnoughRandom => NOT_ENOUGH_RAND,
            OlmGroupSessionError::OutputBufferTooSmall => BUFFER_SMALL,
            OlmGroupSessionError::Unknown => UNKNOWN,
        };
        write!(f, "{}", message)
    }
}
