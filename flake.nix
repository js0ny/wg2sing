{
  description = "WireGuard to Sing-Box endpoints converter";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          lib = pkgs.lib;
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "wg2sing";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            meta = {
              description = "WireGuard to Sing-Box endpoints converter";
              license = lib.licenses.gpl3Plus;
              platforms = lib.platforms.linux;
              mainProgram = "wg2sing";
              sourceProvence = [ lib.sourceTypes.fromSource ];
            };
          };
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          ciDeps = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
          ];
          devDeps = with pkgs; [
            rust-analyzer
          ];
        in
        {
          default = pkgs.mkShell {
            buildInputs = ciDeps ++ devDeps;
          };
        }
      );
    };
}
