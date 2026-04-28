#!/bin/bash

usage() {
  echo "Usage: $0 {jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|prepare_2vc|prepare_2vc_1k|prepare_2vc_2k|prepare_2vc_4k|prepare_2vc_8k|prepare_3vc_1k|prepare_4vc_1k|show_2vc|show_3vc|show_4vc|ecdsa|all}"
  echo "  jwt:    Compile the default JWT circuit."
  echo "  jwt_1k: Compile JWT circuit (1KB - maxMsg=1280)."
  echo "  jwt_2k: Compile JWT circuit (2KB - maxMsg=2048)."
  echo "  jwt_4k: Compile JWT circuit (4KB - maxMsg=4096)."
  echo "  jwt_8k: Compile JWT circuit (8KB - maxMsg=8192)."
  echo "  show:   Compile Show circuit."
  echo "  prepare_*vc*: Compile multi-credential Prepare circuit variants."
  echo "  show_*vc: Compile multi-credential Show circuit variants."
  echo "  ecdsa:  Compile ECDSA circuit."
  echo "  all:    Compile everything — single-VC, 2VC, show, and ecdsa circuits."
  exit 1
}

if [ -z "$1" ]; then
  echo "Error: No option provided."
  usage
fi

# Generic compile function for any named circuit
compile_circuit() {
  local name="$1"
  echo "Compiling circuit: $name"
  npx circomkit compile "$name" || { echo "Error: Failed to compile $name."; exit 1; }
  cd "build/$name/" || { echo "Error: 'build/$name/' directory not found."; exit 1; }
  cp "$name.r1cs" "${name}_js/" || { echo "Error: Failed to copy $name.r1cs."; exit 1; }
  cd ../.. || exit 1
  mkdir -p build/cpp || { echo "Error: Failed to create cpp directory."; exit 1; }
  # Always overwrite so build/cpp/ stays in sync with the freshly compiled circuit.
  # (This used to be guarded with `[ ! -f ... ]`, which silently kept stale copies
  # whenever a circuit was recompiled — leaving downstream consumers like
  # ecdsa-spartan2/build.rs linked against an outdated witness generator.)
  cp "build/$name/${name}_cpp/$name.cpp" build/cpp/ || { echo "Error: Failed to copy $name.cpp."; exit 1; }
  cp "build/$name/${name}_cpp/$name.dat" build/cpp/ || { echo "Error: Failed to copy $name.dat."; exit 1; }
  echo "$name compilation complete."
}

case "$1" in
  jwt|jwt_1k|jwt_2k|jwt_4k|jwt_8k|show|prepare_2vc|prepare_2vc_1k|prepare_2vc_2k|prepare_2vc_4k|prepare_2vc_8k|prepare_3vc_1k|prepare_4vc_1k|show_2vc|show_3vc|show_4vc|ecdsa)
    compile_circuit "$1"
    ;;
  all)
    echo "Compiling all circuits (single-VC + 2VC + ecdsa)..."
    compile_circuit jwt
    compile_circuit jwt_1k
    compile_circuit jwt_2k
    compile_circuit jwt_4k
    compile_circuit jwt_8k
    compile_circuit show
    compile_circuit prepare_2vc
    compile_circuit prepare_2vc_1k
    compile_circuit prepare_2vc_2k
    compile_circuit prepare_2vc_4k
    compile_circuit prepare_2vc_8k
    compile_circuit prepare_3vc_1k
    compile_circuit prepare_4vc_1k
    compile_circuit show_2vc
    compile_circuit show_3vc
    compile_circuit show_4vc
    compile_circuit ecdsa
    echo "All circuits compiled successfully."
    ;;
  *)
    echo "Error: Invalid option '$1'."
    usage
    ;;
esac
