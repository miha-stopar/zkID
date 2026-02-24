use crate::{paths::PathConfig, utils::*, Scalar, E};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::info;

witnesscalc_adapter::witness!(show);

// show.circom
#[derive(Debug, Clone)]
pub struct ShowCircuit {
    /// Path configuration for resolving file paths
    path_config: PathConfig,
    /// Optional override for input JSON path
    input_path: Option<PathBuf>,
    /// Cached witness for reuse across synthesize and shared calls
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for ShowCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl ShowCircuit {
    /// Create a new ShowCircuit with PathConfig and optional input path override.
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Create from just an input path (for backwards compatibility).
    /// Uses development PathConfig.
    pub fn with_input_path<P: Into<Option<PathBuf>>>(path: P) -> Self {
        Self {
            path_config: PathConfig::development(),
            input_path: path.into(),
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    /// Resolve the input JSON path using PathConfig.
    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.input_json("show"))
    }

    /// Get the R1CS file path.
    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path("show")
    }

    /// Get cached witness or generate and cache it.
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();

        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let path = self.resolve_input_json();
        info!("Loading show inputs from {}", path.display());

        let file = std::fs::File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json_value: serde_json::Value =
            serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)?;

        let inputs = parse_show_inputs(&json_value)?;

        info!("Generating witness using witnesscalc...");
        let t0 = Instant::now();

        let inputs_json = hashmap_to_json_string(
            &inputs,
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_substring_length(),
            self.path_config.circuit_size.max_claims_length(),
        )?;
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
        let r1cs_path = self.r1cs_path();

        // Detect if we're in setup phase (ShapeCS) or prove phase (SatisfyingAssignment)
        // During setup, we only need constraint structure instead of actual witness values
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs = load_r1cs(&r1cs_path).map_err(|_| SynthesisError::AssignmentMissing)?;
            // Pass None for witness during setup
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        // Use cached witness (same as shared() used) for soundness
        let witness = self.get_or_generate_witness()?;

        let r1cs = load_r1cs(&r1cs_path).map_err(|_| SynthesisError::AssignmentMissing)?;
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
        let layout =
            calculate_show_witness_indices(self.path_config.circuit_size.max_claims_length());

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
