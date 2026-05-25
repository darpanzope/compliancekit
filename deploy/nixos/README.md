# NixOS module for compliancekit

Drop the module into your NixOS configuration, declare
`services.compliancekit.enable = true;`, and rebuild.

## Usage (flake)

```nix
{
  inputs.compliancekit = {
    url = "github:darpanzope/compliancekit/v1.15.0";
    flake = false; # consume the module directly
  };

  outputs = { self, nixpkgs, compliancekit, ... }: {
    nixosConfigurations.web = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        (compliancekit + "/deploy/nixos/module.nix")
        ({ pkgs, ... }: {
          services.compliancekit = {
            enable = true;
            package = pkgs.callPackage ./compliancekit.nix { };
            dsn = "postgres://compliancekit:CHANGEME@db.internal:5432/compliancekit?sslmode=require";
            addr = "127.0.0.1";
            port = 8080;
            openFirewall = false;
            environment = {
              CK_OIDC_GOOGLE_CLIENT_ID = "...";
            };
          };
        })
      ];
    };
  };
}
```

## Building the binary package

The module expects `cfg.package` to be a derivation that exposes
`bin/compliancekit`. Until compliancekit lands in nixpkgs proper,
the operator supplies a derivation. Minimal example
(`./compliancekit.nix`):

```nix
{ stdenv, fetchurl }:

stdenv.mkDerivation rec {
  pname = "compliancekit";
  version = "1.15.0";

  src = fetchurl {
    url = "https://github.com/darpanzope/compliancekit/releases/download/v${version}/compliancekit_${version}_linux_amd64.tar.gz";
    sha256 = "0000000000000000000000000000000000000000000000000000"; # update via nix-prefetch-url
  };

  sourceRoot = ".";
  installPhase = ''
    install -m 0755 -D compliancekit $out/bin/compliancekit
  '';
}
```

## Secrets

Use `sops-nix` or `agenix` to inject `dsn` + the `environment.CK_*`
secrets without committing plaintext to git.

```nix
services.compliancekit.dsn = "postgres://compliancekit@${config.sops.secrets.ck_db.path}:5432/compliancekit?sslmode=require";
```

(Combine with `sops.secrets.ck_db.owner = "compliancekit";`.)

## Hardening

The module's systemd profile mirrors `deploy/systemd/
compliancekit.service` — `systemd-analyze security compliancekit`
score < 2.0 on a stock NixOS host.
