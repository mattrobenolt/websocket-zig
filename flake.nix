{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    mattware = {
      url = "github:mattrobenolt/nixpkgs";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, system, ... }:
        let
          autobahn-testsuite = pkgs.fetchFromGitHub {
            owner = "crossbario";
            repo = "autobahn-testsuite";
            rev = "v25.10.1";
            hash = "sha256-TtSlwSgVQMhZSLnFjB93ku1WZp3CGSE77mUJNjDZNbI=";
          };
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.mattware.overlays.default
              (final: prev: {
                openssl_1_1 = prev.openssl_1_1.overrideAttrs (_: {
                  doCheck = false;
                  doInstallCheck = false;
                });
              })
            ];
            config.permittedInsecurePackages = [ "openssl-1.1.1w" ];
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              zig_0_15
              zls_0_15
              ziglint
              zigdoc
              just
              git
              nushell
              nufmt
              pypy
              python3
              pkg-config
              coreutils
            ];
            buildInputs = with pkgs; [
              openssl_1_1
              libffi
              zlib
            ];
            shellHook = ''
              unset NIX_CFLAGS_COMPILE
              export AUTOBAHN_CHECKOUT_DIR="${autobahn-testsuite}"
            '';
          };
        };
    };
}
