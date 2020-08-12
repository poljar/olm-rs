#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::{pk, PicklingMode};

fuzz_target!(|data: &[u8]| {
    let pk_dec = pk::OlmPkDecryption::new();

    let mut pickle = pk_dec.pickle(PicklingMode::Unencrypted);
    let _ = pk::OlmPkDecryption::unpickle(pickle, PicklingMode::Unencrypted).unwrap();

    pickle = pk_dec.pickle(PicklingMode::Encrypted { key: data.to_vec() });
    let _ = pk::OlmPkDecryption::unpickle(pickle, PicklingMode::Encrypted { key: data.to_vec() })
        .unwrap();

    let signing = pk::OlmPkSigning::new(data.to_vec());
    if data.len() == pk::OlmPkSigning::seed_length() {
        let signing = signing.unwrap();
        let _ = signing.sign("Untampered");
    } else {
        assert!(signing.is_err());
    }
});
