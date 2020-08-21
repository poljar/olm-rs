#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::sas;

fuzz_target!(|data: String| {
    {  // add scope to test dropping OlmSas
        let s = sas::OlmSas::new();

        let _ = match s.generate_bytes(&data, data.len()) {
            Ok(_) => (),
            Err(_) => (),
        };
    }
});
