//! ECDSA and JWT circuit implementations using Spartan2
//!
//! This library provides zero-knowledge proof circuits for:
//! - ECDSA signature verification
//! - JWT token validation with selective disclosure
//!
//! The circuits use Spartan2's ZK-SNARK protocol with Hyrax polynomial commitment scheme.

use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

pub mod circuit_size;
pub mod circuits;
pub mod paths;
pub mod prover;
#[cfg(not(target_arch = "wasm32"))]
pub mod setup;
pub mod utils;

// Re-export commonly used types and functions
pub use circuit_size::CircuitSize;
pub use circuits::{
    prepare_2vc_circuit::Prepare2VcCircuit, prepare_circuit::PrepareCircuit,
    prepared_multi_link_circuit::PreparedMultiLinkCircuit, show_2vc_circuit::Show2VcCircuit,
    show_circuit::ShowCircuit, show_multi_vc_circuit::ShowMultiVcCircuit,
};
pub use paths::PathConfig;
pub use prover::{generate_prepare_witness, prove_circuit_in_memory, reblind_in_memory};
#[cfg(not(target_arch = "wasm32"))]
pub use prover::{
    generate_shared_blinds, prove_circuit, prove_circuit_with_pk, reblind,
    reblind_with_loaded_data, run_circuit, verify_circuit, verify_circuit_with_loaded_data,
};
#[cfg(not(target_arch = "wasm32"))]
pub use setup::{
    load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
    load_witness, save_keys, setup_circuit_keys, setup_circuit_keys_no_save,
};
pub use utils::{
    bigint_to_scalar, calculate_jwt_output_indices, calculate_prepare_2vc_output_indices,
    calculate_prepared_multi_link_witness_indices, convert_bigint_to_scalar, parse_jwt_inputs,
    parse_prepare_2vc_inputs, parse_prepared_multi_link_inputs, parse_show_inputs, parse_witness,
};
