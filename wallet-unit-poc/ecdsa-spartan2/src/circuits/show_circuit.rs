use crate::{
    utils::{
        calculate_show_witness_indices, hashmap_to_json_string, parse_show_inputs, parse_witness,
        MAX_CLAIMS_LENGTH,
    },
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
    time::Instant,
};
use tracing::info;

witnesscalc_adapter::witness!(show);

#[derive(Debug, Clone)]
pub struct ShowCircuit {
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for ShowCircuit {
    fn default() -> Self {
        Self {
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl ShowCircuit {
    pub fn new<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    fn input_path_absolute(&self, cwd: &PathBuf) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    cwd.join(p)
                }
            })
            .unwrap_or_else(|| cwd.join("../circom/inputs/show/default.json"))
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let cwd = current_dir().unwrap();
        let path = self.input_path_absolute(&cwd);
        info!("Loading show inputs from {}", path.display());

        let file = std::fs::File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json_value: serde_json::Value =
            serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)?;

        let inputs = parse_show_inputs(&json_value)?;

        info!("Generating witness using witnesscalc...");
        let t0 = Instant::now();

        let inputs_json = hashmap_to_json_string(&inputs)?;
        let witness_bytes =
            show_witness(&inputs_json).map_err(|_| SynthesisError::Unsatisfiable)?;

        info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;

        // Cache it
        *cache = Some(witness.clone());

        Ok(witness)
    }
}

impl SpartanCircuit<E> for ShowCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cwd = current_dir().unwrap();
        let root = cwd.join("../circom");
        let r1cs_path = root.join("build/show/show.r1cs");

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        // During setup, we only need constraint structure instead of actual witness values
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(r1cs_path).expect("failed to load R1CS");
            // Pass None for witness during setup
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        // Use cached witness (same as shared() used) for soundness
        let witness = self.get_or_generate_witness()?;

        let r1cs = load_r1cs(r1cs_path).expect("failed to load R1CS");
        synthesize(cs, r1cs, Some(witness))?;
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        // Circom public IO: ageAbove18 (output), deviceKeyX, deviceKeyY (inputs)
        // Witness indices 1..=3
        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(3);
        for idx in 1..=3 {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Calculate witness layout (verified from show.sym)
        let layout = calculate_show_witness_indices(MAX_CLAIMS_LENGTH);

        // Try to get witness; use zeros if unavailable (setup phase)
        // Only attempt witness generation if input path is set (skips during setup)
        let witness = self
            .input_path
            .as_ref()
            .and_then(|_| self.get_or_generate_witness().ok());

        let device_key_x = witness
            .as_ref()
            .map(|w| w[layout.device_key_x_index])
            .unwrap_or(Scalar::ZERO);
        let device_key_y = witness
            .as_ref()
            .map(|w| w[layout.device_key_y_index])
            .unwrap_or(Scalar::ZERO);

        let kb_x = AllocatedNum::alloc(cs.namespace(|| "KeyBindingX"), || Ok(device_key_x))?;
        let kb_y = AllocatedNum::alloc(cs.namespace(|| "KeyBindingY"), || Ok(device_key_y))?;

        let mut shared_values = Vec::with_capacity(2 + layout.claim_len);
        shared_values.push(kb_x);
        shared_values.push(kb_y);

        for idx in 0..layout.claim_len {
            let claim_scalar = witness
                .as_ref()
                .map(|w| w[layout.claim_start + idx])
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
