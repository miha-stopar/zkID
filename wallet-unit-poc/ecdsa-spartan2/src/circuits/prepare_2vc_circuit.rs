use super::synthesize_witness_only;
use crate::{
    paths::PathConfig,
    utils::{
        calculate_prepare_2vc_output_indices, hashmap_to_json_string_prepare_2vc,
        parse_prepare_2vc_inputs, parse_witness,
    },
    Scalar, E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::{reader::load_r1cs, synthesize};
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(all(feature = "native-witness", has_circuit_prepare_2vc_1k))]
witnesscalc_adapter::witness!(prepare_2vc_1k);
#[cfg(all(feature = "native-witness", has_circuit_prepare_2vc_2k))]
witnesscalc_adapter::witness!(prepare_2vc_2k);
#[cfg(all(feature = "native-witness", has_circuit_prepare_2vc_4k))]
witnesscalc_adapter::witness!(prepare_2vc_4k);
#[cfg(all(feature = "native-witness", has_circuit_prepare_2vc_8k))]
witnesscalc_adapter::witness!(prepare_2vc_8k);

#[cfg(feature = "native-witness")]
pub(crate) fn call_prepare_2vc_witness(
    circuit_name: &str,
    inputs_json: &str,
) -> Result<Vec<u8>, SynthesisError> {
    match circuit_name {
        #[cfg(has_circuit_prepare_2vc_1k)]
        "prepare_2vc_1k" => {
            prepare_2vc_1k_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable)
        }
        #[cfg(has_circuit_prepare_2vc_2k)]
        "prepare_2vc_2k" => {
            prepare_2vc_2k_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable)
        }
        #[cfg(has_circuit_prepare_2vc_4k)]
        "prepare_2vc_4k" => {
            prepare_2vc_4k_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable)
        }
        #[cfg(has_circuit_prepare_2vc_8k)]
        "prepare_2vc_8k" => {
            prepare_2vc_8k_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable)
        }
        name => {
            eprintln!(
                "Circuit '{}' is not compiled into this binary.\n\
                 Run `cd ../circom && yarn compile:prepare:2vc:<size>` then rebuild.",
                name
            );
            Err(SynthesisError::Unsatisfiable)
        }
    }
}

#[cfg(not(feature = "native-witness"))]
pub(crate) fn call_prepare_2vc_witness(
    _circuit_name: &str,
    _inputs_json: &str,
) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

#[derive(Debug, Clone)]
pub struct Prepare2VcCircuit {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for Prepare2VcCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl Prepare2VcCircuit {
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

    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path_prepare_2vc()
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }

        let witness = generate_prepare_2vc_witness(
            &self.path_config,
            self.input_path.as_ref().map(|p| p.as_path()),
        )?;
        *cache = Some(witness.clone());
        Ok(witness)
    }
}

#[cfg(feature = "native-witness")]
pub fn generate_prepare_2vc_witness(
    config: &PathConfig,
    input_json_path: Option<&std::path::Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    let json_path = input_json_path
        .map(|p| config.resolve(p))
        .unwrap_or_else(|| config.prepare_2vc_input_json());

    let json_file =
        std::fs::File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;
    let json_value: serde_json::Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    let inputs = parse_prepare_2vc_inputs(&json_value)?;
    let inputs_json = hashmap_to_json_string_prepare_2vc(
        &inputs,
        config.circuit_size.max_matches(),
        config.circuit_size.max_substring_length(),
        config.circuit_size.max_claims_length(),
    )?;

    let witness_bytes =
        call_prepare_2vc_witness(config.circuit_size.prepare_2vc_circuit_name(), &inputs_json)?;
    parse_witness(&witness_bytes)
}

#[cfg(not(feature = "native-witness"))]
pub fn generate_prepare_2vc_witness(
    _config: &PathConfig,
    _input_json_path: Option<&std::path::Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

impl SpartanCircuit<E> for Prepare2VcCircuit {
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
                let layout = calculate_prepare_2vc_output_indices(
                    self.path_config.circuit_size.max_matches(),
                    self.path_config.circuit_size.max_claims_length(),
                );
                synthesize_witness_only(cs, &witness, layout.num_public())?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let layout = calculate_prepare_2vc_output_indices(
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_claims_length(),
        );
        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(layout.num_public());
        for idx in 1..=layout.num_public() {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout = calculate_prepare_2vc_output_indices(
            self.path_config.circuit_size.max_matches(),
            self.path_config.circuit_size.max_claims_length(),
        );

        let witness = {
            let cache = self.cached_witness.lock().unwrap();
            cache.clone()
        }
        .or_else(|| {
            self.input_path
                .as_ref()
                .and_then(|_| self.get_or_generate_witness().ok())
        });

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

        let mut shared_values = Vec::with_capacity(2 + layout.claim_values_len);
        shared_values.push(keybinding_x_alloc);
        shared_values.push(keybinding_y_alloc);

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
