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
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    promessa = {
      url = "git+ssh://git@github.com/pleme-io/promessa";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.crate2nix.follows = "crate2nix";
      inputs.shigoto.follows = "shigoto";
      inputs.shikumi.follows = "shikumi";
      inputs.cofre.follows = "cofre";
    };
    shigoto = {
      url = "git+ssh://git@github.com/pleme-io/shigoto";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.crate2nix.follows = "crate2nix";
    };
    shikumi = {
      url = "git+ssh://git@github.com/pleme-io/shikumi";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.crate2nix.follows = "crate2nix";
    };
    cofre = {
      url = "git+ssh://git@github.com/pleme-io/cofre";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.crate2nix.follows = "crate2nix";
    };
  };
  outputs = inputs @ { self, nixpkgs, flake-utils, substrate, crate2nix, promessa, shigoto, shikumi, cofre, ... }:
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

        # Build both binaries in one workspace cargo invocation — the
        # output derivation contains $out/bin/engenho-promessa AND
        # $out/bin/validation-api, ready to lift into separate images.
        workspaceBinaries = pkgs.rustPlatform.buildRustPackage {
          pname = "engenho-promessa-workspace";
          version = "0.1.0";
          src = composedSrc;
          sourceRoot = "engenho-promessa-composed-src/engenho-promessa";
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "engenho-promessa" "-p" "validation-api" "-p" "validation-crds" ];
          doCheck = false;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          buildInputs = with pkgs; [ openssl ];
        };

        engenho-promessa = workspaceBinaries;
        validation-api  = workspaceBinaries;

        # ── OCI images via dockerTools.buildLayeredImage ──────────────
        # Each image is a small layered tarball:
        #   1. cacert (TLS) + tini (PID 1)
        #   2. the binary
        # Architecture: only the binary's target system is built — for
        # multi-arch images we'd add buildah-style manifests, but
        # pleme-dev is amd64 so one arch is enough.
        mkImage = { name, binary, tag }:
          pkgs.dockerTools.buildLayeredImage {
            inherit name tag;
            contents = with pkgs; [
              cacert
              tini
              bashInteractive       # for `kubectl exec ... -- /bin/sh` debugging
              coreutils
            ];
            config = {
              Entrypoint = [ "/bin/tini" "--" "/bin/${binary}" ];
              Cmd = [ ];
              User = "65532:65532";
              Env = [
                "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
                "RUST_LOG=info"
              ];
              Labels = {
                "org.opencontainers.image.source" =
                  "https://github.com/pleme-io/engenho-promessa-controllers";
                "org.opencontainers.image.title" = binary;
                "org.opencontainers.image.version" = tag;
                "org.opencontainers.image.description" =
                  "AKEYLESS-VALIDATION-PLATFORM ${binary}";
                "pleme.io/theory-ref" =
                  "https://github.com/pleme-io/theory/blob/main/AKEYLESS-VALIDATION-PLATFORM.md";
              };
            };
            extraCommands = ''
              mkdir -p bin
              cp ${workspaceBinaries}/bin/${binary} bin/${binary}
            '';
          };

        engenho-promessa-image = mkImage {
          name = "ghcr.io/pleme-io/engenho-promessa";
          binary = "engenho-promessa";
          tag = "0.1.0";
        };
        validation-api-image = mkImage {
          name = "ghcr.io/pleme-io/validation-api";
          binary = "validation-api";
          tag = "0.1.0";
        };
      in {
        packages = {
          inherit engenho-promessa validation-api
                  engenho-promessa-image validation-api-image;
          default = engenho-promessa;
          "image:engenho-promessa" = engenho-promessa-image;
          "image:validation-api"   = validation-api-image;
        };
        apps.default = { type = "app"; program = "${engenho-promessa}/bin/engenho-promessa"; };
        apps.validation-api = { type = "app"; program = "${validation-api}/bin/validation-api"; };
        devShells.default = pkgs.mkShell {
          name = "engenho-promessa-dev";
          packages = with pkgs; [
            rustc cargo rustfmt clippy rust-analyzer
            pkg-config openssl git jq yq-go
            skopeo
          ];
        };
      }) // {
        overlays.default = final: _prev: {
          engenho-promessa = self.packages.${final.system}.engenho-promessa;
          validation-api   = self.packages.${final.system}.validation-api;
        };
      };
}
