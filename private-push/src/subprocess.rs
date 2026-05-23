//! Thin typed wrappers over `std::process::Command` so the
//! orchestrator's call sites read like intent, not argv plumbing.
//!
//! Two surfaces:
//! - [`run_checked`] — exec a command, panic-free; bubbles up
//!   `anyhow::Error` on non-zero exit with stderr captured
//! - [`run_capture`] — exec + capture stdout for downstream parsing
//! - [`spawn_background`] — fire a long-running child (port-forward);
//!   returns a guard whose Drop kills the child

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, Context, Result};

/// Run a command, inherit stderr, and assert it exits 0.
pub fn run_checked(label: &str, mut cmd: Command) -> Result<()> {
    tracing::debug!(label, ?cmd, "exec");
    let status = cmd
        .status()
        .with_context(|| format!("{label}: spawn failed"))?;
    if !status.success() {
        return Err(anyhow!("{label}: exit {status}"));
    }
    Ok(())
}

/// Run a command and capture stdout. stderr is inherited (visible to
/// the operator). Returns `Ok(stdout)`.
pub fn run_capture(label: &str, mut cmd: Command) -> Result<String> {
    tracing::debug!(label, ?cmd, "capture");
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("{label}: spawn failed"))?;
    if !out.status.success() {
        return Err(anyhow!("{label}: exit {}", out.status));
    }
    Ok(String::from_utf8(out.stdout).with_context(|| format!("{label}: non-utf8 stdout"))?)
}

/// Spawn a long-running command in the background. The returned
/// [`Backgrounded`] kills the child when dropped — wrap the
/// port-forward in one of these and the kubectl session dies on
/// every exit path.
pub fn spawn_background(label: &str, mut cmd: Command) -> Result<Backgrounded> {
    tracing::debug!(label, ?cmd, "spawn background");
    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("{label}: spawn failed"))?;
    Ok(Backgrounded {
        label: label.to_owned(),
        child: Some(child),
    })
}

pub struct Backgrounded {
    label: String,
    child: Option<Child>,
}

impl Backgrounded {
    /// Drain stdout up to the first line matching `predicate` — used
    /// to wait for "Forwarding from 127.0.0.1:5000 -> 5000" before
    /// the orchestrator proceeds.
    pub fn wait_for_line(
        &mut self,
        predicate: impl Fn(&str) -> bool,
        max_lines: usize,
    ) -> Result<()> {
        let Some(child) = self.child.as_mut() else {
            return Err(anyhow!("{}: child already exited", self.label));
        };
        let Some(stdout) = child.stdout.take() else {
            return Err(anyhow!("{}: child has no stdout pipe", self.label));
        };
        let reader = BufReader::new(stdout);
        for (n, line) in reader.lines().enumerate() {
            let line = line.context("read child stdout")?;
            tracing::debug!(label = %self.label, line = %line, "child");
            if predicate(&line) {
                return Ok(());
            }
            if n >= max_lines {
                return Err(anyhow!(
                    "{}: did not match line within {max_lines} lines",
                    self.label
                ));
            }
        }
        Err(anyhow!("{}: child stdout closed before match", self.label))
    }
}

impl Drop for Backgrounded {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            tracing::debug!(label = %self.label, pid = child.id(), "killing background child");
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
