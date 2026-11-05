//! Each buggy vault must be caught, classified correctly and shrunk.

use std::vec;

use soroban_fuzzer::prelude::*;

use super::expect_bug;
use crate::{
    buggy::{
        missing_auth::MissingAuthVault, no_ttl::NoTtlVault, overflow::OverflowVault,
        temp_storage::TempStorageVault, unbounded::UnboundedVault,
    },
    harness::{Action, VaultHarness},
};

#[test]
fn missing_require_auth() {
    expect_bug::<MissingAuthVault>(FailureKind::MissingAuth, 3, |f| f);
}

#[test]
fn missing_auth_regression() {
    type H = VaultHarness<crate::Vault>;
    use crate::harness::Action::Deposit;
    use soroban_fuzzer::strategies::Amount::All;

    Fuzzer::<H>::new()
        .replay(vec![Step::Call(Deposit(ActorId(0), All))])
        .unwrap();
}

#[test]
fn missing_require_auth_found_by_unsigned_probe() {
    // With the recorded-auth check off, the unsigned replay still catches it.
    expect_bug::<MissingAuthVault>(FailureKind::AuthBypass, 3, |f| {
        f.check_auths(false).check_unsigned_calls()
    });
}

#[test]
fn balances_in_temporary_storage() {
    expect_bug::<TempStorageVault>(FailureKind::InvariantViolated, 3, |f| f);
}

#[test]
fn temporary_storage_bug_needs_time_to_pass() {
    // Without ledger jumps the temporary-storage vault looks correct.
    Fuzzer::<VaultHarness<TempStorageVault>>::new()
        .seed(1)
        .cases(64)
        .without_ledger_jumps()
        .run()
        .unwrap();
}

#[test]
fn missing_ttl_extension() {
    expect_bug::<NoTtlVault>(FailureKind::ArchivedEntry, 3, |f| f);
}

#[test]
fn arithmetic_overflow() {
    expect_bug::<OverflowVault>(FailureKind::UnexpectedPanic, 2, |f| f);
}

#[test]
fn unbounded_storage_reads() {
    // A team budget of 12 footprint entries per call. The correct vault needs
    // about 7; this one adds one read per historical deposit.
    expect_bug::<UnboundedVault>(FailureKind::ResourceBudgetExceeded, 8, |f| {
        f.steps(1..=48).resource_budget(ResourceBudget {
            max_footprint_entries: 12,
            ..ResourceBudget::default()
        })
    });
}

#[test]
fn unbounded_storage_reads_hit_network_limits() {
    // With no headroom budget, enough deposits make the call itself fail
    // inside the Env's mainnet limit enforcement.
    let steps = (0..420)
        .map(|_| Step::Call(Action::Deposit(ActorId(0), Amount::Exact(1))))
        .collect();
    let err = Fuzzer::<VaultHarness<UnboundedVault>>::new()
        .resource_budget(ResourceBudget::UNLIMITED)
        .replay(steps)
        .unwrap_err();
    assert_eq!(err.kind, FailureKind::ResourceLimitExceeded, "{err}");
}
