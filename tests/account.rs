use olm_rs::{account::OlmAccount, session::OlmSession, utility::OlmUtility};

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
fn signatures_valid() {
    // test signature being valid base64
    let olm_account = OlmAccount::new();
    let message = "Hello world!";
    let mut signature = olm_account.sign(message);
    base64::decode(&signature).unwrap();

    let utility = OlmUtility::new();
    let ed25519_key_json = json::parse(&olm_account.identity_keys()).unwrap();
    let ed25519_key = ed25519_key_json["ed25519"].as_str().unwrap();
    assert!(utility
        .ed25519_verify(&ed25519_key, message, &mut signature)
        .unwrap());
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
pub fn parse_identity_keys_correct() {
    let account = OlmAccount::new();
    let identity_keys_json = json::parse(&account.identity_keys()).unwrap();
    let identity_keys_parsed = account.parsed_identity_keys();
    assert_eq!(
        identity_keys_parsed.curve25519,
        identity_keys_json["curve25519"]
    );
    assert_eq!(identity_keys_parsed.ed25519, identity_keys_json["ed25519"]);
}