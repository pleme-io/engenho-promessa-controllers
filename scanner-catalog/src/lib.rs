//! `scanner-catalog` — typed catalog of every scanner the AKEYLESS-
//! VALIDATION-PLATFORM can spawn. One `ScannerImpl` per
//! [`validation_crds::ScannerKind`] variant — OCI image + CLI args
//! template + target-field shape + output-format parser.
//!
//! ## Why a separate crate
//!
//! Reusability across ecosystems:
//!
//! | Consumer | Use |
//! |---|---|
//! | `validation-controllers::scan_job` | Spawns K8s Jobs against each catalog entry |
//! | kenshi `BuildPipeline` | Pre-flight scanner runs before promotion |
//! | Future tatara processes | `(defscanner :kind grype …)` declarations resolve here |
//! | SDK generators | OpenAPI / GraphQL surfaces the typed scanner inventory |
//! | Operator tooling | `validation-api scanners ls` lists what's wired |
//!
//! All of those consume the **same** typed surface — fleet-coherent
//! per VIGGY-AUTHORING macros-everywhere + Compounding Directive #1.
//!
//! ## Adding a scanner
//!
//! 1. Add a variant to [`validation_crds::ScannerKind`] (the CRD enum)
//! 2. Add a parallel variant to
//!    `security_controller::RequiredScanner` (the typed surface)
//! 3. Add a [`ScannerImpl`] entry in [`catalog::Catalog::for_kind`]
//! 4. Add a parser in [`parsers`] for the scanner's output format
//! 5. Add a unit test in `tests/<scanner>_golden.rs` with a real
//!    sample of the scanner's output
//!
//! Steps 1+2 are CRD/typed-surface changes; steps 3-5 are this crate.

#![allow(clippy::module_name_repetitions)]

pub mod catalog;
pub mod parsers;

pub use catalog::{
    mirror_image, ArgsTemplate, Catalog, OutputFormat, ScannerImpl, TargetField,
};
pub use parsers::{parse_scanner_output, ParserError};

// Re-export the CRD enums so consumers don't need a separate
// validation-crds dep for the common case.
pub use validation_crds::{ScanFinding, ScanFindingSeverity, ScannerClass, ScannerKind};
