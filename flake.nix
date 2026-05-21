{
  description = "Per-kind TargetControllers under the Viggy Method (theory/VIGGY-LEGOS.md Part VII). Each crate is one TargetController kind from the canonical set: SLA, CostBudget, Compliance, CustomerKpi, Security, Custom. First crate shipped: security-controller — drives the Akeyless FedRAMP High SCR program (ASM-17571). Implements diff/classify/decide as pure functions over the kind's Snapshot shape; mandates trait_laws_obeyed!(<Kind>Controller) macro expansion across all 10 invariants (VIGGY-AUTHORING §10.1). Consumes pleme-io/promessa for the TargetController trait and pleme-io/pangea-operator for TypedAction dispatch.";
  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs?ref=nixos-unstable";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    promessa = {
      url = "git+ssh://git@github.com/pleme-io/promessa";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    shigoto = {
      url = "git+ssh://git@github.com/pleme-io/shigoto";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    shikumi = {
      url = "git+ssh://git@github.com/pleme-io/shikumi";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    cofre = {
      url = "git+ssh://git@github.com/pleme-io/cofre";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = inputs @ { self, nixpkgs, flake-utils, substrate, promessa, shigoto, shikumi, cofre, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        cleanSelf = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: _:
            let rel = pkgs.lib.removePrefix (toString ./.) (toString path);
            in !(builtins.match "^/target(/.*)?$" rel != null
                 || builtins.match "^/result.*$" rel != null
                 || builtins.match ".*/\\.direnv(/.*)?$" rel != null);
        };

        composedSrc = pkgs.runCommand "engenho-promessa-composed-src" {} ''
          mkdir -p $out/engenho-promessa
          cp -r ${cleanSelf}/. $out/engenho-promessa/
          chmod -R +w $out/engenho-promessa
          cp -r ${promessa} $out/promessa
          chmod -R +w $out/promessa
          cp -r ${shigoto} $out/shigoto
          chmod -R +w $out/shigoto
          cp -r ${shikumi} $out/shikumi
          chmod -R +w $out/shikumi
          cp -r ${cofre} $out/cofre
          chmod -R +w $out/cofre
        '';

        engenho-promessa = pkgs.rustPlatform.buildRustPackage {
          pname = "engenho-promessa";
          version = "0.1.0";
          src = composedSrc;
          sourceRoot = "engenho-promessa-composed-src/engenho-promessa";
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "engenho-promessa" ];
          cargoTestFlags  = [ "-p" "engenho-promessa" ];
          doCheck = false;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
        };
      in {
        packages = { inherit engenho-promessa; default = engenho-promessa; };
        apps.default = { type = "app"; program = "${engenho-promessa}/bin/engenho-promessa"; };
        devShells.default = pkgs.mkShell {
          name = "engenho-promessa-dev";
          packages = with pkgs; [
            rustc cargo rustfmt clippy rust-analyzer
            pkg-config openssl git jq yq-go
          ];
        };
      }) // {
        overlays.default = final: _prev: { engenho-promessa = self.packages.${final.system}.engenho-promessa; };
      };
}
