use std::fmt;

use crate::runner::Step;

/// The class of bug a failing case points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// `Harness::setup` panicked.
    Setup,
    /// `apply` returned `Err`: the contract disagreed with the model.
    ModelMismatch,
    /// A user invariant returned `Err` (or panicked).
    InvariantViolated,
    /// A contract call panicked with an unexpected error (overflow, unwrap,
    /// contract error from a non-`try_` call, …).
    UnexpectedPanic,
    /// A persistent or instance entry expired (got archived) within the
    /// ledger horizon: it was not kept alive with `extend_ttl`.
    ArchivedEntry,
    /// A call exceeded the network limits enforced by the test `Env`.
    ResourceLimitExceeded,
    /// A call stayed under the network limits but over the configured
    /// [`ResourceBudget`](crate::ResourceBudget) headroom.
    ResourceBudgetExceeded,
    /// A declared signer did not authorise the call: missing `require_auth`.
    MissingAuth,
    /// The action still changed the ledger when replayed with no signatures
    /// (see [`Fuzzer::check_unsigned_calls`](crate::Fuzzer::check_unsigned_calls)).
    AuthBypass,
}

impl FailureKind {
    /// Short hint printed with the failure.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Setup => "the harness setup itself failed",
            Self::ModelMismatch => "the contract's result differs from the model",
            Self::InvariantViolated => "a harness invariant no longer holds",
            Self::UnexpectedPanic => "a contract call panicked",
            Self::ArchivedEntry => {
                "an entry expired: extend its TTL on access (or use a longer TTL)"
            }
            Self::ResourceLimitExceeded => {
                "a call exceeded network limits: look for unbounded loops or reads"
            }
            Self::ResourceBudgetExceeded => {
                "a call is close to network limits: it may fail as state grows"
            }
            Self::MissingAuth => "a signer was not required: add `require_auth()`",
            Self::AuthBypass => "the call works without any signature: enforce `require_auth()`",
        }
    }

    /// Classify a panic message coming out of a contract call.
    ///
    /// Matches the host's structured error code rather than free text, so a
    /// contract panic that merely mentions "budget" is not misclassified.
    pub(crate) fn from_panic(msg: &str) -> Self {
        if msg.contains("Error(Budget, ExceededLimit)") {
            Self::ResourceLimitExceeded
        } else {
            Self::UnexpectedPanic
        }
    }
}

/// A minimal failing case found by the fuzzer.
#[derive(Clone)]
pub struct FuzzFailure<A> {
    pub kind: FailureKind,
    pub message: String,
    /// Index in `steps` of the step that failed (`None` for setup or the
    /// initial invariant check).
    pub step: Option<usize>,
    /// The shrunk sequence of steps that reproduces the failure.
    pub steps: Vec<Step<A>>,
    /// Seed of the run, to replay it with `SOROBAN_FUZZ_SEED`.
    pub seed: u64,
}

impl<A: fmt::Debug> fmt::Display for FuzzFailure<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "soroban-fuzzer found a failing case: {:?}", self.kind)?;
        writeln!(f, "  hint: {}", self.kind.hint())?;
        writeln!(f, "  minimal sequence ({} steps):", self.steps.len())?;
        for (i, s) in self.steps.iter().enumerate() {
            let mark = if self.step == Some(i) {
                "  <-- failed here"
            } else {
                ""
            };
            writeln!(f, "    {i:>3}: {s:?}{mark}")?;
        }
        writeln!(f, "  regression test:")?;
        writeln!(f, "    Fuzzer::<H>::new().replay(vec![")?;
        for step in &self.steps {
            match step {
                Step::Call(action) => writeln!(f, "        Step::Call({action:?}),")?,
                Step::AdvanceLedger(n) => {
                    writeln!(f, "        Step::AdvanceLedger({n}),")?
                }
            }
        }
        writeln!(f, "    ]).unwrap();")?;
        writeln!(f, "  error: {}", first_lines(&self.message, 12))?;
        write!(f, "  replay: SOROBAN_FUZZ_SEED={} cargo test", self.seed)
    }
}

impl<A: fmt::Debug> fmt::Debug for FuzzFailure<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<A: fmt::Debug> std::error::Error for FuzzFailure<A> {}

fn first_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= n {
        s.to_string()
    } else {
        format!(
            "{}\n  … ({} more lines)",
            lines[..n].join("\n"),
            lines.len() - n
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_host_errors_by_code() {
        let host = "HostError: Error(Budget, ExceededLimit)\n  event log …";
        assert_eq!(
            FailureKind::from_panic(host),
            FailureKind::ResourceLimitExceeded
        );
        assert_eq!(
            FailureKind::from_panic("my contract ran over budget"),
            FailureKind::UnexpectedPanic
        );
        assert_eq!(
            FailureKind::from_panic("attempt to add with overflow"),
            FailureKind::UnexpectedPanic
        );
    }

    #[test]
    fn report_marks_the_failing_step() {
        let f = FuzzFailure {
            kind: FailureKind::MissingAuth,
            message: "boom".into(),
            step: Some(1),
            steps: vec![Step::Call("a"), Step::AdvanceLedger(5), Step::Call("b")],
            seed: 9,
        };
        let text = f.to_string();
        assert!(
            text.contains("1: <advance 5 ledgers>  <-- failed here"),
            "{text}"
        );
        assert!(
            text.contains(
                "Fuzzer::<H>::new().replay(vec![\n        Step::Call(\"a\"),\n        Step::AdvanceLedger(5),\n        Step::Call(\"b\"),\n    ]).unwrap();"
            ),
            "{text}"
        );
        assert!(text.contains("SOROBAN_FUZZ_SEED=9"), "{text}");
        assert!(text.contains(FailureKind::MissingAuth.hint()), "{text}");
    }

    #[test]
    fn long_messages_are_truncated() {
        let long: String = (0..50).map(|i| format!("line {i}\n")).collect();
        let shown = first_lines(&long, 12);
        assert!(shown.contains("line 11") && !shown.contains("line 12"));
        assert!(shown.contains("38 more lines"));
    }
}
