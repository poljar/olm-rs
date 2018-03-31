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
