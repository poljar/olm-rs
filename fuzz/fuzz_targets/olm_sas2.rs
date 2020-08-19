#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::sas;

fuzz_target!(|data: String| {
    {  // add scope to test dropping OlmSas
        let mut s = sas::OlmSas::new();

        if data.len() != s.public_key().len() {
            return ()
        }

        let _ = match s.set_their_public_key(data.clone()) {
            // calculate mac when other public key is set
            Ok(_) => s.calculate_mac(&data, &data).unwrap(),
            Err(e) => format!("{:?}", e),
        };
    }
});
