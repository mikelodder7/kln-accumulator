// SPDX-License-Identifier: MIT OR Apache-2.0
//! The size report: one markdown table of the encoded size, in bytes, of every key, value,
//! witness, update message and membership proof, for each variant, parameter set and trapdoor
//! distribution. Every figure is the length of a real value's packed encoding. Run with
//! `cargo bench --bench sizes`; printing the table is this binary's purpose.
//!
//! Membership proofs exist only for Construction 4.1 at the toy set; every other proof cell is
//! `n/a`. The succinct 128-bit set is left out: its public key would be about 110 GiB.

#[path = "support/adaptive.rs"]
pub mod adaptive;
#[path = "support/base.rs"]
pub mod base;
#[path = "support/common.rs"]
pub mod common;
#[path = "support/proving.rs"]
pub mod proving;
#[path = "support/succinct.rs"]
pub mod succinct;
#[path = "support/variant.rs"]
pub mod variant;

use adaptive::Adaptive;
use base::Base;
use common::{Outcome, params, trapdoor_name};
use kln_accumulator::{ParamsSpec, TrapdoorDistribution};
use proving::{LEVELS, Proving};
use strum::IntoEnumIterator;
use succinct::Succinct;
use variant::{Fixture, Variant};

/// The table's columns after variant, set and trapdoor.
const COLUMNS: [&str; 9] = [
    "secret key",
    "public key",
    "accumulator",
    "witness",
    "update message",
    "proof",
    "proof, 1 level",
    "proof, 2 levels",
    "proof, 3 levels",
];

/// The cells of a size that cannot exist.
const ABSENT: &str = "n/a";

/// Where a row comes from: variant, parameter set and trapdoor distribution.
struct Row<'a> {
    /// The parameter set's name.
    set: &'a str,
    /// The parameter set.
    spec: ParamsSpec,
    /// The trapdoor distribution.
    trapdoor: TrapdoorDistribution,
}

impl Row<'_> {
    /// Prints the row of `fixture`, with the sizes of `proving`'s proofs or `n/a`.
    fn print<V: Variant>(&self, fixture: &Fixture<V>, proving: Option<&Proving>) -> Outcome<()> {
        let message = fixture
            .coefficients
            .first()
            .ok_or("the fixture published no update message")?;
        let mut cells = vec![
            V::key_bytes(&fixture.key).to_string(),
            V::public_bytes(&fixture.public).to_string(),
            V::value_bytes(&fixture.value).to_string(),
            V::witness_bytes(&fixture.witness)?.to_string(),
            message.to_bytes().len().to_string(),
        ];
        match proving {
            Some(proving) => {
                cells.push(proving.proof.to_bytes().len().to_string());
                cells.extend(
                    proving
                        .compressed
                        .iter()
                        .map(|compressed| Vec::from(compressed).len().to_string()),
                );
            }
            None => cells.extend((0..=LEVELS.len()).map(|_| ABSENT.to_owned())),
        }
        println!(
            "| {} | {} | {} | {} |",
            V::NAME,
            self.set,
            trapdoor_name(self.trapdoor),
            cells.join(" | ")
        );
        Ok(())
    }

    /// Builds the fixture of variant `V` for this row and prints it without proofs.
    fn fixture<V: Variant>(&self) -> Outcome<()> {
        self.print(
            &Fixture::<V>::new(params(self.spec, self.trapdoor)?, 1)?,
            None,
        )
    }

    /// Builds Construction 4.1's fixture with its proofs for this row and prints both.
    fn proved(&self) -> Outcome<()> {
        let proving = Proving::new(params(self.spec, self.trapdoor)?)?;
        self.print(&proving.linked.fixture, Some(&proving))
    }
}

fn main() -> Outcome<()> {
    // `cargo bench -- --list` passes `--list` to every target: this one has no benchmarks.
    if std::env::args().any(|arg| arg == "--list") {
        return Ok(());
    }
    println!(
        "| variant | parameter set | trapdoor | {} |",
        COLUMNS.join(" | ")
    );
    println!("|---|---|---|{}", "---:|".repeat(COLUMNS.len()));
    let rows = |set, spec| {
        TrapdoorDistribution::iter().map(move |trapdoor| Row {
            set,
            spec,
            trapdoor,
        })
    };
    for row in rows("toy", ParamsSpec::TOY) {
        row.proved()?;
    }
    for row in rows("paper-128", ParamsSpec::PAPER_128) {
        row.fixture::<Base>()?;
    }
    for row in rows("toy", ParamsSpec::TOY) {
        row.fixture::<Adaptive>()?;
    }
    for row in rows("succinct-toy", ParamsSpec::SUCCINCT_TOY) {
        row.fixture::<Succinct>()?;
    }
    Ok(())
}
