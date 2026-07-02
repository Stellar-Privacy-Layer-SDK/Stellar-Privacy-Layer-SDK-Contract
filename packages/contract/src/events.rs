use soroban_sdk::{Address, Env};

use crate::types::*;

pub fn emit_deposit(e: &Env, event: &DepositEvent) {
    e.events().publish(
        ("ShieldedPool", "deposit"),
        (event.depositor.clone(), event.commitment.clone()),
    );
}

pub fn emit_withdrawal(e: &Env, event: &WithdrawalEvent) {
    e.events().publish(
        ("ShieldedPool", "withdrawal"),
        (event.recipient.clone(), event.nullifier.clone()),
    );
}

pub fn emit_compliance_set(e: &Env, owner: &Address, viewer: &Address) {
    e.events()
        .publish(("ShieldedPool", "compliance_set"), (owner, viewer));
}
