# blackmatter-anvil wiring example — Claude Code + akeyless validation MCP
#
# Drop this fragment into your home-manager configuration to make the
# akeyless validation pipeline's compliance state queryable from
# Claude Code (and any other MCP client anvil registers).
#
# Two things land:
#   1. `anvil.mcp.servers.akeyless-validation` — points at the
#      `validation-api mcp-proxy` stdio→HTTP bridge
#   2. `anvil.contexts.claude-akeyless` — org-scoped Claude wrapper
#      that auto-includes this MCP server
#
# Once flush:
#   $ claude-akeyless        # launches Claude Code with the MCP wired
#   Claude can call:
#     - tools/list           → enumerates the 6 validation tools
#     - tools/call name=compliance_summary → cluster-wide phase/verdict counts
#     - tools/call name=list_blocked       → every image stuck on Failed/Quarantined
#     - tools/call name=list_validations service=auth
#     - tools/call name=query_findings severity=Critical
#     - tools/call name=get_validation namespace=akeyless-validation name=…
#     - tools/call name=trigger_rescan namespace=… name=…
#
# Bearer token lives in a SOPS-encrypted file mounted at
# `/run/secrets/akeyless-mcp-bearer` (operator's home-manager pulls
# from sops-nix; see `pleme-io/nix/secrets.yaml` for the encrypted
# entry naming convention).

{ config, pkgs, lib, ... }:

{
  # ─── 1. MCP server registration ──────────────────────────────────
  blackmatter.components.anvil.mcp.servers.akeyless-validation = {
    description = "Akeyless validation pipeline — compliance state of every image";

    # The `validation-api` binary is built from
    # pleme-io/engenho-promessa-controllers and lands on PATH via
    # the same nix-flake output that the cluster pulls. For local
    # operator use, build with:
    #   nix build path:///home/drzzln/code/github/pleme-io/engenho-promessa-controllers#validation-api
    # then home.packages = [ (selfFlake.packages.${system}.validation-api) ];
    command = "validation-api";

    args = [
      "mcp-proxy"
      "--endpoint"
      "https://validation-api.dev.use1.quero.lol/v1/mcp"
      "--bearer-file"
      "/run/secrets/akeyless-mcp-bearer"
      "--timeout-secs" "30"
    ];

    # Scope this server to the akeyless context only — never surfaces
    # in pleme-org or personal Claude wrappers.
    scopes = [ "akeyless" ];
  };

  # ─── 2. Org-scoped Claude wrapper ────────────────────────────────
  # `anvil.contexts.<name>` builds a `claude-<name>` wrapper binary
  # that auto-includes every MCP server whose `scopes` contains the
  # context's `scope` field.
  blackmatter.components.anvil.contexts.claude-akeyless = {
    scope = "akeyless";
    env = {
      # Inherit any akeyless-specific env (region, profile, etc.)
      # the operator wants baked into every Claude session inside
      # this context.
      AWS_PROFILE = "akeyless-development";
    };
    agents.claude = {
      enable = true;
    };
  };

  # ─── 3. Op-side reminders (operator config, not anvil) ───────────
  # SOPS secret for the bearer:
  #
  #   sops.secrets."akeyless-mcp-bearer" = {
  #     sopsFile = ./secrets.yaml;
  #     key = "akeyless/mcp-bearer";
  #     mode = "0400";
  #     # Match the path in args above.
  #     path = "/run/secrets/akeyless-mcp-bearer";
  #   };
  #
  # Token bytes match the `MCP_BEARER_TOKEN` env on the
  # validation-api Deployment in pleme-dev (operator creates both
  # halves from the same source).
}
