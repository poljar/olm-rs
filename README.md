# olm-rs

This project is dedicated towards creating a safe wrapper for [libolm](https://git.matrix.org/git/olm/about/) and an easy management solution for E2E encryption for [Matrix](https://matrix.org/) clients in Rust.

Matrix room for discussion: *!dtTRILMxRNPsJTSpfH:matrix.org*

Currently the wrapper part of this library is being implemented while the management functionality is being planned for. Please note that this library is not production ready!

### Building

For generating the C bindings used by this library, you first have to install libolm: 
```
$ git clone https://git.matrix.org/git/olm
$ cd olm
$ make
# make install
```

After that it's just a simple `cargo build`.

### Contributing
If you are considering to contribute, take a look at the CONTRIBUTING guide.

### Licensing
This project is licensed under the GPLv3+ license - for further information see the LICENSE file.
