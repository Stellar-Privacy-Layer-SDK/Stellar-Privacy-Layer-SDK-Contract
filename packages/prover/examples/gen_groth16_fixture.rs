//! Generates the committed Groth16 fixture used by the contract tests.
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run -p stellar-privacy-prover --example gen_groth16_fixture
//! ```
//!
//! The fixture is written to
//! `packages/contract/test_snapshots/groth16/fixture.json` and MUST be
//! committed — `stellar-privacy-contract` embeds it with `include_str!` so
//! contract tests verify a real arkworks-generated proof on-chain. The prover
//! test `test_committed_fixture_is_valid` re-verifies it with arkworks, so a
//! stale or mismatched fixture fails CI.

use stellar_privacy_prover::groth16::*;

fn main() {
    let mut rng = deterministic_rng(0xBEEF_F00D);
    let values = demo_values();
    let (pk, vk) = setup(&mut rng);
    let proof = prove(&mut rng, &pk, &values);
    let public_inputs = vec![values.commitment, values.nullifier];

    // Sanity-check with the arkworks reference verifier before writing.
    assert!(
        verify(&vk, &public_inputs, &proof),
        "generated proof must verify"
    );

    let fixture = build_fixture(&vk, &proof, &public_inputs);
    let json = serde_json::to_string_pretty(&fixture).expect("serialize fixture");

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out_path = manifest_dir.join("../contract/test_snapshots/groth16/fixture.json");
    std::fs::create_dir_all(out_path.parent().expect("fixture dir")).expect("create fixture dir");
    std::fs::write(&out_path, json).expect("write fixture");

    println!(
        "wrote {} (circuit: {}, {} public inputs)",
        out_path.display(),
        fixture.circuit,
        fixture.public_inputs.len(),
    );
}
