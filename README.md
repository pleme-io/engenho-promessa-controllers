# engenho-promessa-controllers

> Per-kind TargetControllers under the Viggy Method (theory/VIGGY-LEGOS.md Part VII). Each crate is one TargetController kind from the canonical set: SLA, CostBudget, Compliance, CustomerKpi, Security, Custom. First crate shipped: security-controller — drives the Akeyless FedRAMP High SCR program (ASM-17571). Implements diff/classify/decide as pure functions over the kind's Snapshot shape; mandates trait_laws_obeyed!(<Kind>Controller) macro expansion across all 10 invariants (VIGGY-AUTHORING §10.1). Consumes pleme-io/promessa for the TargetController trait and pleme-io/pangea-operator for TypedAction dispatch.

## Building

```bash
nix run .#engenho-promessa -- --help
```

## License

MIT.
