#![no_main]
#[macro_use] extern crate libfuzzer_sys;

use olm_rs::{utility::OlmUtility};
fuzz_target!(|data: &[u8]| {

    let util = OlmUtility::new();
    util.sha256_bytes(data);

});
