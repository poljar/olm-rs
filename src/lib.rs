extern crate olm_sys;
extern crate ring;

mod account;

#[cfg(test)]
mod tests {
    use account::OlmAccount;

    #[test]
    fn test_olm_account() {
        let mut olm_account = OlmAccount::new();
        let identity_keys = olm_account.identity_keys();
        println!("{}", &identity_keys)
    }
}
