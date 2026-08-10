//! Real Groth16 proof verification on-chain (BLS12-381).
//!
//! Implements the full Groth16 verification equation using Stellar's native
//! BLS12-381 host functions (`env.crypto().bls12_381()`):
//!
//! ```text
//! e(A, B) · e(-α, β) · e(-Σᵢ γ_abc[i]·pub[i], γ) · e(-C, δ) = 1
//! ```
//!
//! equivalently written as the pairing product
//! `e(-A, B) · e(α, β) · e(msm, γ) · e(C, δ) == 1` where
//! `msm = γ_abc[0] + Σᵢ pub[i]·γ_abc[i+1]` is computed with one multi-scalar
//! multiplication.
//!
//! Point encoding follows the Soroban host-function convention:
//!
//! - `G1Affine`: 96 bytes, uncompressed `x ‖ y` (48 bytes each, big-endian)
//! - `G2Affine`: 192 bytes, uncompressed `x_c1 ‖ x_c0 ‖ y_c1 ‖ y_c0`
//! - `Fr`: 32 bytes, big-endian scalar (reduced mod `r`)
//!
//! Fixtures in the exact same encoding are produced by the prover crate
//! (`stellar-privacy-prover::groth16`) and committed under
//! `test_snapshots/groth16/`, so the contract tests verify a real
//! arkworks-generated proof end-to-end.
//!
//! Security: every point in the proof is subgroup-checked before the pairing
//! check (rejects small-subgroup attacks). The verifying key is validated once
//! at `set_groth16_vk` time so per-withdrawal verification stays cheap.

use soroban_sdk::crypto::bls12_381::{Fr, G1Affine, G2Affine};
use soroban_sdk::{BytesN, Env, Vec};

use crate::types::*;

/// Scalar size in bytes.
pub const FR_SIZE: usize = 32;

/// The number of public inputs the shielded-transfer demo circuit exposes.
/// Convention: `public_inputs = [commitment, nullifier]`.
pub const GROTH16_PUBLIC_INPUTS: u32 = 2;

/// Validates a Groth16 verifying key: every point must deserialize and lie in
/// the correct prime-order subgroup, and no element may be degenerate (the
/// all-zero encoding or a point with the infinity flag set). Called once at
/// `set_groth16_vk` time.
pub fn vk_is_valid(e: &Env, vk: &Groth16Vk) -> bool {
    let bls = e.crypto().bls12_381();

    if vk_is_degenerate(&vk.alpha_g1)
        || vk_is_degenerate(&vk.beta_g2)
        || vk_is_degenerate(&vk.gamma_g2)
        || vk_is_degenerate(&vk.delta_g2)
    {
        return false;
    }

    let alpha = G1Affine::from_bytes(vk.alpha_g1.clone());
    if !bls.g1_is_in_subgroup(&alpha) {
        return false;
    }

    let beta = G2Affine::from_bytes(vk.beta_g2.clone());
    let gamma = G2Affine::from_bytes(vk.gamma_g2.clone());
    let delta = G2Affine::from_bytes(vk.delta_g2.clone());
    if !bls.g2_is_in_subgroup(&beta)
        || !bls.g2_is_in_subgroup(&gamma)
        || !bls.g2_is_in_subgroup(&delta)
    {
        return false;
    }

    if vk.gamma_abc_g1.len() != GROTH16_PUBLIC_INPUTS + 1 {
        return false;
    }
    for i in 0..vk.gamma_abc_g1.len() {
        let p = G1Affine::from_bytes(vk.gamma_abc_g1.get_unchecked(i).clone());
        if !bls.g1_is_in_subgroup(&p) || vk_is_degenerate(&vk.gamma_abc_g1.get_unchecked(i)) {
            return false;
        }
    }
    true
}

/// True for degenerate point encodings: all-zero bytes, or the point at
/// infinity (infinity flag `0x40` set in the first byte).
fn vk_is_degenerate<const N: usize>(bytes: &BytesN<N>) -> bool {
    let arr = bytes.to_array();
    arr == [0u8; N] || arr[0] & 0x40 != 0
}

/// Full Groth16 verification: structural checks, subgroup checks, public-input
/// MSM, and the final pairing product.
pub fn verify_groth16(e: &Env, vk: &Groth16Vk, proof: &Groth16Proof) -> bool {
    let bls = e.crypto().bls12_381();

    // --- structural checks ---
    let num_inputs = proof.public_inputs.len();
    if num_inputs != GROTH16_PUBLIC_INPUTS || vk.gamma_abc_g1.len() != num_inputs + 1 {
        return false;
    }

    // --- parse + subgroup-check the proof points ---
    let a = G1Affine::from_bytes(proof.a.clone());
    let b = G2Affine::from_bytes(proof.b.clone());
    let c = G1Affine::from_bytes(proof.c.clone());
    if !bls.g1_is_in_subgroup(&a) || !bls.g2_is_in_subgroup(&b) || !bls.g1_is_in_subgroup(&c) {
        return false;
    }

    let alpha = G1Affine::from_bytes(vk.alpha_g1.clone());
    let beta = G2Affine::from_bytes(vk.beta_g2.clone());
    let gamma = G2Affine::from_bytes(vk.gamma_g2.clone());
    let delta = G2Affine::from_bytes(vk.delta_g2.clone());

    // --- public-input MSM: γ_abc[0] + Σᵢ pub[i]·γ_abc[i+1] ---
    let mut points = Vec::new(e);
    let mut scalars = Vec::new(e);

    let mut one_bytes = [0u8; FR_SIZE];
    one_bytes[FR_SIZE - 1] = 1;
    points.push_back(G1Affine::from_bytes(
        vk.gamma_abc_g1.get_unchecked(0).clone(),
    ));
    scalars.push_back(Fr::from_bytes(BytesN::from_array(e, &one_bytes)));

    for i in 0..num_inputs {
        points.push_back(G1Affine::from_bytes(
            vk.gamma_abc_g1.get_unchecked(i + 1).clone(),
        ));
        scalars.push_back(Fr::from_bytes(proof.public_inputs.get_unchecked(i).clone()));
    }
    let msm = bls.g1_msm(points, scalars);

    // --- pairing product: e(-A, B) · e(α, β) · e(msm, γ) · e(C, δ) == 1 ---
    let mut lhs_g1 = Vec::new(e);
    lhs_g1.push_back(-a.clone());
    lhs_g1.push_back(alpha);
    lhs_g1.push_back(msm);
    lhs_g1.push_back(c);

    let mut lhs_g2 = Vec::new(e);
    lhs_g2.push_back(b);
    lhs_g2.push_back(beta);
    lhs_g2.push_back(gamma);
    lhs_g2.push_back(delta);

    bls.pairing_check(lhs_g1, lhs_g2)
}
