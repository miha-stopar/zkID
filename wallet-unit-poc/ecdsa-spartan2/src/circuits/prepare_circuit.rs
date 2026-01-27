use crate::{
    prover::generate_prepare_witness,
    utils::{calculate_jwt_output_indices, MAX_CLAIMS_LENGTH, MAX_MATCHES},
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    env::current_dir,
    path::PathBuf,
    sync::{Arc, Mutex},
};

witnesscalc_adapter::witness!(jwt);

/// PrepareCircuit wraps the JWT verification circuit.
#[derive(Debug, Clone)]
pub struct PrepareCircuit {
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for PrepareCircuit {
    fn default() -> Self {
        Self {
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl PrepareCircuit {
    pub fn new<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    fn input_path_absolute(&self, cwd: &PathBuf) -> Option<PathBuf> {
        self.input_path.as_ref().map(|p| {
            if p.is_absolute() {
                p.clone()
            } else {
                cwd.join(p)
            }
        })
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let cwd = current_dir().unwrap();
        let input_path = self.input_path_absolute(&cwd);
        let witness = generate_prepare_witness(input_path.as_ref().map(|p| p.as_path()))?;

        *cache = Some(witness.clone());

        Ok(witness)
    }
}

impl SpartanCircuit<E> for PrepareCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cwd = current_dir().unwrap();
        let root = cwd.join("../circom");
        let witness_dir = root.join("build/jwt/jwt_js");
        let r1cs_path = witness_dir.join("jwt.r1cs");

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        // During setup, we only need constraint structure instead of actual witness values
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(r1cs_path);
            // Pass None for witness during setup
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        let r1cs = load_r1cs(r1cs_path);
        synthesize(cs, r1cs, Some(witness))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Calculate witness layout
        let layout = calculate_jwt_output_indices(MAX_MATCHES, MAX_CLAIMS_LENGTH);

        // Only attempt witness generation if input path is set (skips during setup)
        let witness = self
            .input_path
            .as_ref()
            .and_then(|_| self.get_or_generate_witness().ok());

        let keybinding_x = witness
            .as_ref()
            .map(|w| w[layout.keybinding_x_index])
            .unwrap_or(Scalar::ZERO);
        let keybinding_y = witness
            .as_ref()
            .map(|w| w[layout.keybinding_y_index])
            .unwrap_or(Scalar::ZERO);

        let keybinding_x_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(keybinding_x))?;
        let keybinding_y_alloc =
            AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(keybinding_y))?;

        let mut shared_values = Vec::with_capacity(2 + layout.age_claim_len);
        shared_values.push(keybinding_x_alloc);
        shared_values.push(keybinding_y_alloc);

        for idx in 0..layout.age_claim_len {
            let claim_scalar = witness
                .as_ref()
                .map(|w| w[layout.age_claim_start + idx])
                .unwrap_or(Scalar::ZERO);
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("Claim{idx}")), move || {
                    Ok(claim_scalar)
                })?;
            shared_values.push(claim_alloc);
        }

        Ok(shared_values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}
