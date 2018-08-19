# olm-rs

This project is dedicated towards creating a safe wrapper for [libolm](https://git.matrix.org/git/olm/about/) in Rust.

Matrix room for discussion: *[#olm-rs:matrix.org](https://matrix.to/#/#olm-rs:matrix.org)*

The usage of this library is currently discouraged, as it still lacks a lot of testing and the API is guaranteed to change in major ways.

### Building

`libolm` is compiled and statically linked on building `olm-sys` - so no further setup is required.
Please note however that `libolm` still needs `libstdc++` on your system (and it should already be there).

### Contributing
If you are considering to contribute, take a look at the CONTRIBUTING guide.

### Licensing
This project is licensed under the GPLv3+ license - for further information see the LICENSE file.
