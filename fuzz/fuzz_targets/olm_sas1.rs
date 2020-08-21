#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::sas;

fuzz_target!(|data: String| {
    {
        // add scope to test dropping OlmSas
        let s1 = sas::OlmSas::new();
        let mut s2 = sas::OlmSas::new();
        assert!(s2.set_their_public_key(s1.public_key()).is_ok());

        assert!(s1.generate_bytes(&data, data.len()).is_err());
        assert!(s2.generate_bytes(&data, data.len()).is_ok());
    }
});
