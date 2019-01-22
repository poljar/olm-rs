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

use olm_rs::account::OlmAccount;
use olm_rs::errors::{OlmAccountError, OlmSessionError};
use olm_rs::inbound_group_session::OlmInboundGroupSession;
use olm_rs::outbound_group_session::OlmOutboundGroupSession;
use olm_rs::session::{OlmMessageType, OlmSession};
use olm_rs::utility::OlmUtility;
use olm_rs::*;

#[test]
fn library_version_valid() {
    let invalid_olm_version = OlmVersion {
        major: 0,
        minor: 0,
        patch: 0,
    };
    let olm_version = olm_rs::get_library_version();
    println!(
        "Olm version: {}.{}.{}",
        olm_version.major, olm_version.minor, olm_version.patch
    );
    assert_ne!(olm_version, invalid_olm_version);
}

#[test]
fn identity_keys_valid() {
    let olm_account = OlmAccount::new();
    // verify length of entire JSON object
    let identity_keys = olm_account.identity_keys();
    assert_eq!(identity_keys.len(), 116);
    let keys_json = json::parse(&identity_keys).unwrap();
    let curve25519 = String::from(keys_json["curve25519"].as_str().unwrap());
    let ed25519 = String::from(keys_json["ed25519"].as_str().unwrap());
    // verify encoded keys length
    assert_eq!(curve25519.len(), 43);
    assert_eq!(ed25519.len(), 43);
    // encoded as valid base64?
    base64::decode(&curve25519).unwrap();
    base64::decode(&ed25519).unwrap();
}

#[test]
fn operational_rng() {
    // Check that generated keys aren't the same
    let olm_account = OlmAccount::new();
    let olm_account2 = OlmAccount::new();
    let identity_keys = olm_account.identity_keys();
    let identity_keys2 = olm_account2.identity_keys();
    assert_ne!(identity_keys, identity_keys2);
}

#[test]
fn signatures_valid() {
    // test signature being valid base64
    let olm_account = OlmAccount::new();
    let bytes = vec![72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33];
    let signature = olm_account.sign_bytes(bytes.as_slice());
    assert_eq!(signature.len(), 86);
    base64::decode(&signature).unwrap();

    // test sign_bytes() and sign_utf8_msg() on identical input
    let message = String::from("Hello world!");
    assert_eq!(
        olm_account.sign_bytes(message.as_bytes()),
        olm_account.sign_utf8_msg(message.as_str())
    )
}

#[test]
fn one_time_keys_valid() {
    let olm_account = OlmAccount::new();
    let max_number_otks = olm_account.max_number_of_one_time_keys();
    assert_eq!(100, max_number_otks);

    // empty read of one time keys
    let otks_empty = olm_account.one_time_keys();
    let otks_empty_json = json::parse(&otks_empty).unwrap();
    assert!(otks_empty_json["curve25519"].is_object());
    assert!(otks_empty_json["curve25519"].is_empty());

    olm_account.generate_one_time_keys(20);
    let otks_filled = olm_account.one_time_keys();
    let otks_filled_json = json::parse(&otks_filled).unwrap();
    assert_eq!(20, otks_filled_json["curve25519"].len());
    for entry in otks_filled_json["curve25519"].entries() {
        assert_eq!(6, entry.0.len());
        let key = entry.1.as_str().unwrap();
        base64::decode(&key).unwrap();
    }

    olm_account.mark_keys_as_published();

    // empty read of one time keys after marking as published
    let otks_empty = olm_account.one_time_keys();
    let otks_empty_json = json::parse(&otks_empty).unwrap();
    assert!(otks_empty_json["curve25519"].is_object());
    assert!(otks_empty_json["curve25519"].is_empty());
}

#[test]
fn remove_one_time_keys() {
    let account_a = OlmAccount::new();
    account_a.generate_one_time_keys(1);

    let account_b = OlmAccount::new();
    account_b.generate_one_time_keys(1);

    let otks = json::parse(&account_b.one_time_keys()).unwrap();
    let identity_keys = json::parse(&account_b.identity_keys()).unwrap();
    let session = OlmSession::create_outbound_session(
        &account_a,
        &identity_keys["curve25519"].as_str().unwrap(),
        &otks["curve25519"]
            .entries()
            .nth(0)
            .unwrap()
            .1
            .as_str()
            .unwrap(),
    )
    .unwrap();

    assert_eq!(1, otks["curve25519"].len());

    account_b.remove_one_time_keys(&session).unwrap();

    // empty read of one time keys after removing
    let otks_empty = json::parse(&account_b.one_time_keys()).unwrap();
    assert!(otks_empty["curve25519"].is_object());
    assert!(otks_empty["curve25519"].is_empty());
}

#[test]
#[should_panic(expected = "called `Result::unwrap()` on an `Err` value: BadMessageKeyId")]
fn remove_one_time_keys_fails() {
    let account_a = OlmAccount::new();
    account_a.generate_one_time_keys(1);

    let account_b = OlmAccount::new();
    account_b.generate_one_time_keys(1);

    let otks = json::parse(&account_b.one_time_keys()).unwrap();
    let identity_keys = json::parse(&account_b.identity_keys()).unwrap();
    let session = OlmSession::create_outbound_session(
        &account_a,
        &identity_keys["curve25519"].as_str().unwrap(),
        &otks["curve25519"]["AAAAAQ"].as_str().unwrap(),
    )
    .unwrap();

    assert_eq!(1, otks["curve25519"].len());

    account_a.remove_one_time_keys(&session).unwrap();
}

#[test]
fn sha256_valid() {
    let mut test_str = String::from("Hello, World!");
    let util = OlmUtility::new();
    let mut test_str_same = String::from("Hello, World!");
    let test_str_bytes = unsafe { test_str_same.as_bytes_mut() };

    assert_eq!(
        util.sha256_utf8_msg(&mut test_str),
        util.sha256_bytes(test_str_bytes)
    )
}

#[test]
fn account_pickling_fails_on_wrong_key() {
    let pickled;
    {
        let olm_account = OlmAccount::new();
        pickled = olm_account.pickle(&[3, 2, 1]);
    }
    // wrong key
    let olm_account_bad = OlmAccount::unpickle(pickled, &[1, 2, 3]);

    assert!(olm_account_bad.is_err());
    assert_eq!(olm_account_bad.err(), Some(OlmAccountError::BadAccountKey));
}

fn create_session_pair() -> (OlmSession, OlmSession) {
    let pickled_account_a = String::from("eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x");
    let pickled_account_b = String::from("eModTvoFi9oOIkax4j4nuxw9Tcl/J8mOmUctUWI68Q89HSaaPTqR+tdlKQ85v2GOs5NlZCp7EuycypN9GQ4fFbHUCrS7nspa3GFBWsR8PnM8+wez5PWmfFZLg3drOvT0jbMjpDx0MjGYClHBqcrEpKx9oFaIRGBaX6HXzT4lRaWSJkXxuX92q8iGNrLn96PuAWFNcD+2JXpPcNFntslwLUNgqzpZ04aIFYwL80GmzyOgq3Bz1GO6u3TgCQEAmTIYN2QkO0MQeuSfe7UoMumhlAJ6R8GPcdSSPtmXNk4tdyzzlgpVq1hm7ZLKto+g8/5Aq3PvnvA8wCqno2+Pi1duK1pZFTIlActr");
    let account_a = OlmAccount::unpickle(pickled_account_a, &[]).unwrap();
    let account_b = OlmAccount::unpickle(pickled_account_b, &[]).unwrap();
    let _identity_key_a = String::from("qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o");
    let _one_time_key_a = String::from("WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk");
    let identity_key_b = String::from("q/YhJtog/5VHCAS9rM9uUf6AaFk1yPe4GYuyUOXyQCg");
    let one_time_key_b = String::from("oWvzryma+B2onYjo3hM6A3Mgo/Yepm8HvgSvwZMTnjQ");
    let outbound =
        OlmSession::create_outbound_session(&account_a, &identity_key_b, &one_time_key_b).unwrap();
    let pre_key = outbound.encrypt(""); // Payload does not matter for PreKey
    let inbound = OlmSession::create_inbound_session(&account_b, pre_key).unwrap();
    (inbound, outbound)
}

#[test]
fn olm_outbound_session_creation() {
    let (_, outbound_session) = create_session_pair();

    assert_eq!(
        OlmMessageType::PreKey,
        outbound_session.encrypt_message_type()
    );
    assert!(!outbound_session.has_received_message());
}

#[test]
fn olm_encrypt_decrypt() {
    let (inbound_session, outbound_session) = create_session_pair();
    let encrypted = outbound_session.encrypt("Hello world!");
    let decrypted = inbound_session
        .decrypt(outbound_session.encrypt_message_type(), encrypted)
        .unwrap();
    assert_eq!(decrypted, "Hello world!");
}

#[test]
fn session_pickling_valid() {
    let pickled_account_a = String::from("eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x");
    let account_a = OlmAccount::unpickle(pickled_account_a, &[]).unwrap();
    let identity_key_b = String::from("qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o");
    let one_time_key_b = String::from("WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk");
    let outbound_session =
        OlmSession::create_outbound_session(&account_a, &identity_key_b, &one_time_key_b).unwrap();

    let session_id_before = outbound_session.session_id();
    let pickled_session = outbound_session.pickle(&[]);

    let outbound_session_unpickled = OlmSession::unpickle(pickled_session, &[]).unwrap();
    let session_id_after = outbound_session_unpickled.session_id();
    assert_eq!(session_id_before, session_id_after);
}

#[test]
fn session_pickling_fails_on_wrong_key() {
    let pickled_account_a = String::from("eOBXIKivUT6YYowRH031BNv7zNmzqM5B7CpXdyeaPvala5mt7/OeqrG1qVA7vA1SYloFyvJPIy0QNkD3j1HiPl5vtZHN53rtfZ9exXDok03zjmssqn4IJsqcA7Fbo1FZeKafG0NFcWwCPTdmcV7REqxjqGm3I4K8MQFa45AdTGSUu2C12cWeOcbSMlcINiMral+Uyah1sgPmLJ18h1qcnskXUXQvpffZ5DiUw1Iz5zxnwOQF1GVyowPJD7Zdugvj75RQnDxAn6CzyvrY2k2CuedwqDC3fIXM2xdUNWttW4nC2g4InpBhCVvNwhZYxlUb5BUEjmPI2AB3dAL5ry6o9MFncmbN6x5x");
    let account_a = OlmAccount::unpickle(pickled_account_a, &[]).unwrap();
    let identity_key_b = String::from("qIEr3TWcJQt4CP8QoKKJcCaukByIOpgh6erBkhLEa2o");
    let one_time_key_b = String::from("WzsbsjD85iB1R32iWxfJdwkgmdz29ClMbJSJziECYwk");
    let outbound_session =
        OlmSession::create_outbound_session(&account_a, &identity_key_b, &one_time_key_b).unwrap();
    let pickled_session = outbound_session.pickle(&[3, 2, 1]);

    // wrong key
    let outbound_session_bad = OlmSession::unpickle(pickled_session, &[1, 2, 3]);
    assert!(outbound_session_bad.is_err());
    assert_eq!(
        outbound_session_bad.err(),
        Some(OlmSessionError::BadAccountKey)
    );
}

#[test]
fn group_session_pickling_valid() {
    let ogs = OlmOutboundGroupSession::new();
    let ogs_id = ogs.session_id();
    // ID is valid base64?
    base64::decode(&ogs_id).unwrap();

    // no messages have been sent yet
    assert_eq!(0, ogs.session_message_index());

    let ogs_pickled = ogs.pickle(&[]);
    let ogs = OlmOutboundGroupSession::unpickle(&ogs_pickled, &[]).unwrap();
    assert_eq!(ogs_id, ogs.session_id());

    let igs = OlmInboundGroupSession::new(&ogs.session_key()).unwrap();
    let igs_id = igs.session_id();
    // ID is valid base64?
    base64::decode(&igs_id).unwrap();

    // no messages have been sent yet
    assert_eq!(0, igs.first_known_index());

    let igs_pickled = igs.pickle(&[]);
    let igs = OlmInboundGroupSession::unpickle(igs_pickled, &[]).unwrap();
    assert_eq!(igs_id, igs.session_id());
}

#[test]
/// Send message from A to B
fn group_session_crypto_valid() {
    let ogs = OlmOutboundGroupSession::new();
    let igs = OlmInboundGroupSession::new(&ogs.session_key()).unwrap();

    assert_eq!(ogs.session_id(), igs.session_id());

    let plaintext = String::from("Hello world!");
    let ciphertext = ogs.encrypt(plaintext);
    // ciphertext valid base64?
    base64::decode(&ciphertext).unwrap();

    let decryption_result = igs.decrypt(ciphertext).unwrap();

    // correct plaintext?
    assert_eq!(String::from("Hello world!"), decryption_result.0);

    // first message sent, so the message index is zero
    assert_eq!(0, decryption_result.1);
}
