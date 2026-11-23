// SPDX-License-Identifier: MIT OR Apache-2.0
//! Printing encoded sizes next to the figures of Table 2.

use std::time::{Duration, Instant};

/// One mebibyte; Table 2's sizes follow when its MB is read as MiB.
pub const MIB: f64 = 1024.0 * 1024.0;

/// One kibibyte.
pub const KIB: f64 = 1024.0;

/// Runs `step`, prints its wall time under `name`, and returns its result.
pub fn timed<T>(name: &str, step: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = step();
    eprintln!("  {name}: {}", seconds(start.elapsed()));
    value
}

fn seconds(elapsed: Duration) -> String {
    format!("{:.2} s", elapsed.as_secs_f64())
}

/// Prints `bytes` in bytes, KiB and MiB, and its ratio to `paper` (in `unit` bytes) when given.
pub fn report(name: &str, bytes: usize, paper: Option<(f64, f64, &str)>) {
    let size = bytes as f64;
    let line = format!(
        "  {name}: {bytes} bytes = {:.2} KiB = {:.3} MiB",
        size / KIB,
        size / MIB
    );
    match paper {
        Some((figure, unit, label)) => eprintln!(
            "{line}; Table 2: {figure} {label}, ratio {:.4}",
            size / (figure * unit)
        ),
        None => eprintln!("{line}"),
    }
}

/// Fails unless `bytes` is within 10% of `figure · unit` bytes.
pub fn assert_within_ten_percent(name: &str, bytes: usize, figure: f64, unit: f64) {
    let ratio = bytes as f64 / (figure * unit);
    assert!(
        (ratio - 1.0).abs() <= 0.10,
        "{name}: {bytes} bytes is {ratio:.4} times Table 2's figure"
    );
}
