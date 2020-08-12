#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::pk;

fuzz_target!(|data_str: String| {
    let mut pk_enc = pk::OlmPkEncryption::new(data_str.clone());
    let _ = pk_enc.encrypt("Top secret!");

    let pk_enc2 = pk::OlmPkEncryption::new("".to_string());
    let _ = pk_enc2.encrypt(&data_str);

    let pk_dec = pk::OlmPkDecryption::new();
    pk_enc = pk::OlmPkEncryption::new(pk_dec.public_key().to_owned());

    let msg = pk_enc.encrypt(&data_str);
    let _ = pk_dec.decrypt(msg).unwrap();

    let signing = pk::OlmPkSigning::new(vec![0; pk::OlmPkSigning::seed_length()]).unwrap();
    let _ = signing.sign(&data_str);
});
