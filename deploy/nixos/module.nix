# v1.15 phase 6 — NixOS module for compliancekit.
#
# Import in your configuration.nix / flake module set:
#
#   imports = [ /path/to/compliancekit/deploy/nixos/module.nix ];
#   services.compliancekit = {
#     enable = true;
#     dsn = "postgres://compliancekit:CHANGEME@db.internal:5432/compliancekit?sslmode=require";
#     addr = "127.0.0.1";
#     port = 8080;
#     openFirewall = false;
#     extraArgs = [ ];
#   };
#
# The module creates a `compliancekit` system user, declares a
# tmpfiles rule for /var/lib/compliancekit, and registers a
# systemd unit with the same hardening profile as the deploy/
# systemd unit.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.compliancekit;
in
{
  options.services.compliancekit = {
    enable = lib.mkEnableOption "compliancekit daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.compliancekit or null;
      description = ''
        The compliancekit package. When the operator's nixpkgs
        overlay defines pkgs.compliancekit, the module uses it
        automatically; otherwise the operator passes the binary
        in via pkgs.callPackage / pkgs.runCommand.
      '';
    };

    dsn = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/compliancekit/serve.db";
      description = ''
        Database location. SQLite path (default) or a postgres://
        DSN. Pass via NixOS secret / age / sops-nix in production
        rather than committing.
      '';
    };

    addr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Bind address. Use 127.0.0.1 + a reverse proxy in production.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Listen port.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the configured port in the host firewall.";
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "--insecure-cookies" ];
      description = "Extra arguments appended to `serve`.";
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        CK_OIDC_GOOGLE_CLIENT_ID = "...";
      };
      description = "Extra environment variables (auth providers / plugins / etc).";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.compliancekit = {
      isSystemUser = true;
      group = "compliancekit";
      home = "/var/lib/compliancekit";
      createHome = true;
      shell = "${pkgs.shadow}/bin/nologin";
    };
    users.groups.compliancekit = { };

    systemd.tmpfiles.rules = [
      "d /var/lib/compliancekit 0750 compliancekit compliancekit -"
    ];

    networking.firewall.allowedTCPPorts =
      lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.compliancekit = {
      description = "compliancekit daemon";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = cfg.environment;

      serviceConfig = {
        Type = "simple";
        User = "compliancekit";
        Group = "compliancekit";
        WorkingDirectory = "/var/lib/compliancekit";
        ExecStart = lib.concatStringsSep " " ([
          "${cfg.package}/bin/compliancekit"
          "serve"
          "--addr"  cfg.addr
          "--port"  (toString cfg.port)
          "--db"    cfg.dsn
        ] ++ cfg.extraArgs);

        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = 30;

        # Hardening — mirror the deploy/systemd unit.
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/compliancekit" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged @resources" ];
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];
        UMask = "0027";
        LimitNOFILE = 65536;
        LimitNPROC = 4096;
      };
    };
  };
}
