# copied expressions from https://nixos.wiki/wiki/Rust
# and Mozilla's nix overlay README
# https://www.scala-native.org/en/latest/user/setup.html
let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
in
  with pkgs;
  stdenv.mkDerivation {
    name = "clang-env-with-nightly-rust";
    buildInputs = [
      pkgs.latest.rustChannels.nightly.rust
      clang
      llvmPackages.libclang
      olm
    ];
    # why do we need to set the library path manually?
    shellHook = ''
      export LIBCLANG_PATH="${pkgs.llvmPackages.libclang}/lib";
    '';
  }
