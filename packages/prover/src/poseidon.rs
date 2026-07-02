use ark_bn254::Fr;
use ark_ff::AdditiveGroup;

const T: usize = 3;
const NR_FULL: usize = 8;
const NR_PARTIAL: usize = 57;

fn mds_matrix() -> [[Fr; T]; T] {
    [
        [Fr::from(3u64), Fr::from(1u64), Fr::from(1u64)],
        [Fr::from(1u64), Fr::from(-1i64), Fr::from(1u64)],
        [Fr::from(1u64), Fr::from(1u64), Fr::from(-1i64)],
    ]
}

fn generate_round_constants() -> [[Fr; T]; NR_FULL + NR_PARTIAL] {
    let mut rcs = [[Fr::ZERO; T]; NR_FULL + NR_PARTIAL];
    for (i, rc_row) in rcs.iter_mut().enumerate() {
        for (j, rc) in rc_row.iter_mut().enumerate() {
            *rc = Fr::from((i * T + j + 1) as u64);
        }
    }
    rcs
}

pub struct Poseidon {
    round_constants: [[Fr; T]; NR_FULL + NR_PARTIAL],
    mds: [[Fr; T]; T],
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon {
    pub fn new() -> Self {
        Poseidon {
            round_constants: generate_round_constants(),
            mds: mds_matrix(),
        }
    }

    pub fn hash(&self, inputs: Vec<Fr>) -> Result<Fr, &'static str> {
        if inputs.len() > T - 1 {
            return Err("too many inputs for Poseidon t=3");
        }

        let mut state = [Fr::ZERO; T];
        for (i, input) in inputs.iter().enumerate() {
            state[i] = *input;
        }

        let total_rounds = NR_FULL + NR_PARTIAL;
        let half_full = NR_FULL / 2;
        let partial_end = half_full + NR_PARTIAL;
        for r in 0..total_rounds {
            for (i, s) in state.iter_mut().enumerate() {
                *s += self.round_constants[r][i];
            }

            if !(half_full..partial_end).contains(&r) {
                for s in state.iter_mut() {
                    *s = self.sbox(*s);
                }
            } else {
                state[0] = self.sbox(state[0]);
            }

            state = self.mix(state);
        }

        Ok(state[1])
    }

    fn sbox(&self, x: Fr) -> Fr {
        let x2 = x * x;
        let x4 = x2 * x2;
        x4 * x
    }

    fn mix(&self, state: [Fr; T]) -> [Fr; T] {
        let mut result = [Fr::ZERO; T];
        for (i, r) in result.iter_mut().enumerate() {
            for (j, m) in self.mds[i].iter().enumerate() {
                *r += *m * state[j];
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_basic() {
        let poseidon = Poseidon::new();
        let inputs = vec![Fr::from(1u64), Fr::from(2u64)];
        let hash = poseidon.hash(inputs).unwrap();
        assert_ne!(hash, Fr::ZERO);
    }

    #[test]
    fn test_poseidon_deterministic() {
        let poseidon = Poseidon::new();
        let inputs1 = vec![Fr::from(42u64), Fr::from(99u64)];
        let inputs2 = vec![Fr::from(42u64), Fr::from(99u64)];
        assert_eq!(
            poseidon.hash(inputs1).unwrap(),
            poseidon.hash(inputs2).unwrap()
        );
    }

    #[test]
    fn test_poseidon_diff_inputs_diff_outputs() {
        let poseidon = Poseidon::new();
        let h1 = poseidon.hash(vec![Fr::from(1u64), Fr::from(2u64)]).unwrap();
        let h2 = poseidon.hash(vec![Fr::from(2u64), Fr::from(1u64)]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon_rejects_too_many_inputs() {
        let poseidon = Poseidon::new();
        let result = poseidon.hash(vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon_sbox_property() {
        let poseidon = Poseidon::new();
        let x = Fr::from(3u64);
        let y = poseidon.sbox(x);
        let expected = x * x * x * x * x;
        assert_eq!(y, expected);
    }
}
