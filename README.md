# olm-rs

This project is dedicated towards creating a safe wrapper for [libolm](https://git.matrix.org/git/olm/about/) and an easy management solution for E2E encryption for [Matrix](https://matrix.org/) clients in Rust.

Matrix room for discussion: *#olm-rs:matrix.org*

Currently the wrapper part of this library is being implemented while the management functionality is being planned for. Please note that this library is not production ready!

### Building

For generating the C bindings used by this library, you first have to install libolm.

#### Debian

Debian has packages for libolm in testing (buster) and unstable (sid), called libolm2 and libolm-dev.
They can be installed with the following command:

`# apt install libolm2 libolm-dev`

#### Arch Linux

There is a package in the AUR for libolm under the name libolm. Use your AUR helper of choice or clone
the AUR package and install with:

`$ makepkg -si`

#### Manual Install

If your distribution does not ship libolm, you can install it with the following commands:

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
