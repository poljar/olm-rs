#![no_main]
use libfuzzer_sys::fuzz_target;

use olm_rs::{pk, PicklingMode};

fuzz_target!(|data: &[u8]| {
    // encryption and decryption
    {
        if let Ok(pk_str) = String::from_utf8(data.to_vec()) {
            let mut pk_enc = pk::OlmPkEncryption::new(pk_str.clone());
            let _ = pk_enc.encrypt(&pk_str);

            let pk_dec = pk::OlmPkDecryption::new();
            pk_enc = pk::OlmPkEncryption::new(pk_dec.public_key().to_owned());

            let msg = pk_enc.encrypt(&pk_str);
            let _ = pk_dec.decrypt(msg).unwrap();

            let mut pickle = pk_dec.pickle(PicklingMode::Unencrypted);
            let _ = pk::OlmPkDecryption::unpickle(pickle, PicklingMode::Unencrypted).unwrap();


            pickle = pk_dec.pickle(PicklingMode::Encrypted{ key: data.to_vec() });
            let _ = pk::OlmPkDecryption::unpickle(pickle, PicklingMode::Encrypted{ key: data.to_vec() }).unwrap();
        }
    }

    // signing
    {
        if let Ok(signing) = pk::OlmPkSigning::new(data.to_vec()) {
            if let Ok(msg_str) = String::from_utf8(data.to_vec()) {
                let _ = signing.sign(&msg_str);
            }
        }
    }
});
