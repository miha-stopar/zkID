use super::synthesize_witness_only;
use crate::{
    paths::PathConfig,
    utils::{
        calculate_show_witness_indices, hashmap_to_json_string, parse_show_inputs, parse_witness,
    },
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
#[cfg(feature = "native-witness")]
use std::time::Instant;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing::info;

#[cfg(all(feature = "native-witness", has_circuit_show_2vc))]
witnesscalc_adapter::witness!(show_2vc);

#[cfg(all(feature = "native-witness", has_circuit_show_2vc))]
fn call_show_2vc_witness(inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    show_2vc_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable)
}

#[cfg(not(all(feature = "native-witness", has_circuit_show_2vc)))]
fn call_show_2vc_witness(_inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

#[derive(Debug, Clone)]
pub struct Show2VcCircuit {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for Show2VcCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl Show2VcCircuit {
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_witness(witness: Vec<Scalar>) -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(Some(witness))),
        }
    }

    fn resolve_input_json(&self) -> PathBuf {
        self.input_path
            .as_ref()
            .map(|p| self.path_config.resolve(p))
            .unwrap_or_else(|| self.path_config.show_2vc_input_json())
    }

    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path_show_2vc()
    }

    #[cfg(feature = "native-witness")]
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let path = self.resolve_input_json();
        info!("Loading show_2vc inputs from {}", path.display());

        let file = std::fs::File::open(&path).map_err(|_| SynthesisError::AssignmentMissing)?;
        let json_value: serde_json::Value =
            serde_json::from_reader(file).map_err(|_| SynthesisError::AssignmentMissing)?;
        let inputs = parse_show_inputs(&json_value)?;

        let inputs_json = hashmap_to_json_string(
            &inputs,
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_substring_length(),
            self.path_config.circuit_size.max_claims_length(),
        )?;

        let t0 = Instant::now();
        let witness_bytes = call_show_2vc_witness(&inputs_json)?;
        info!("show_2vc witnesscalc time: {} ms", t0.elapsed().as_millis());

        let witness = parse_witness(&witness_bytes)?;
        *cache = Some(witness.clone());
        Ok(witness)
    }

    #[cfg(not(feature = "native-witness"))]
    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let cache = self.cached_witness.lock().unwrap();
        cache.clone().ok_or(SynthesisError::AssignmentMissing)
    }
}

impl SpartanCircuit<E> for Show2VcCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");

        if is_setup_phase {
            let r1cs =
                load_r1cs(&self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            synthesize(cs, r1cs, None)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;
        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                synthesize(cs, r1cs, Some(witness))?;
            }
            Err(_) => {
                synthesize_witness_only(cs, &witness, 3)?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
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
        let layout = calculate_show_witness_indices(self.path_config.circuit_size.n_claims_2vc());
        let witness = {
            let cache = self.cached_witness.lock().unwrap();
            cache.clone()
        }
        .or_else(|| {
            self.input_path
                .as_ref()
                .and_then(|_| self.get_or_generate_witness().ok())
        });

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

        let mut shared_values = Vec::with_capacity(2 + layout.claim_values_len);
        shared_values.push(kb_x);
        shared_values.push(kb_y);

        for idx in 0..layout.claim_values_len {
            let claim_scalar = witness
                .as_ref()
                .map(|w| w[layout.claim_values_start + idx])
                .unwrap_or(Scalar::ZERO);
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("ClaimValue{idx}")), move || {
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
