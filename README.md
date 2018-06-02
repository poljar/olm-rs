# olm-rs

This project is dedicated towards creating a safe wrapper for [libolm](https://git.matrix.org/git/olm/about/) and an easy management solution for E2E encryption for [Matrix](https://matrix.org/) clients in Rust.

Matrix room for discussion: *[#olm-rs:matrix.org](https://matrix.to/#/#olm-rs:matrix.org)*

Currently the wrapper part of this library is being implemented while the management functionality is being planned for. Please note that this library is not production ready!

### Building

`libolm` is compiled and statically linked on building `olm-sys` - so no further setup is required.
Please note however that `libolm` still needs `libstdc++` on your system (and it should already be there).

### Contributing
If you are considering to contribute, take a look at the CONTRIBUTING guide.

### Licensing
This project is licensed under the GPLv3+ license - for further information see the LICENSE file.
