#!/bin/bash
set -euo pipefail

# Build the Spartan2 WASM module using wasm-pack
# This compiles the Rust prover to WebAssembly for use in the SDK

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(dirname "$SCRIPT_DIR")"
WASM_DIR="$SDK_DIR/wasm"

echo "=== Building OpenAC WASM module ==="
echo "WASM crate: $WASM_DIR"

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build with wasm-pack
echo "Building WASM module..."
cd "$WASM_DIR"
wasm-pack build \
    --target web \
    --out-dir pkg \
    --release \
    -- \
    --features "getrandom/js"

echo "=== WASM build complete ==="
echo "Output: $WASM_DIR/pkg/"

# Copy circuit artifacts if they exist
CIRCOM_BUILD="$SDK_DIR/../circom/build"
ASSETS_DIR="$SDK_DIR/assets"

if [ -d "$CIRCOM_BUILD" ]; then
    echo "Copying circuit artifacts to assets/..."

    # R1CS files
    if [ -f "$CIRCOM_BUILD/jwt/jwt_js/jwt.r1cs" ]; then
        cp "$CIRCOM_BUILD/jwt/jwt_js/jwt.r1cs" "$ASSETS_DIR/jwt.r1cs"
        echo "  Copied jwt.r1cs"
    fi

    if [ -f "$CIRCOM_BUILD/show/show_js/show.r1cs" ]; then
        cp "$CIRCOM_BUILD/show/show_js/show.r1cs" "$ASSETS_DIR/show.r1cs"
        echo "  Copied show.r1cs"
    fi

    # Witness calculator WASM files
    if [ -f "$CIRCOM_BUILD/jwt/jwt_js/jwt.wasm" ]; then
        cp "$CIRCOM_BUILD/jwt/jwt_js/jwt.wasm" "$ASSETS_DIR/jwt.wasm"
        echo "  Copied jwt.wasm (witness calculator)"
    fi

    if [ -f "$CIRCOM_BUILD/show/show_js/show.wasm" ]; then
        cp "$CIRCOM_BUILD/show/show_js/show.wasm" "$ASSETS_DIR/show.wasm"
        echo "  Copied show.wasm (witness calculator)"
    fi

    # 2VC witness calculator WASM files. The SDK's fixed 2VC path currently
    # uses the 1k Prepare variant, matching the default 2VC key size.
    if [ -f "$CIRCOM_BUILD/prepare_2vc_1k/prepare_2vc_1k_js/prepare_2vc_1k.wasm" ]; then
        cp "$CIRCOM_BUILD/prepare_2vc_1k/prepare_2vc_1k_js/prepare_2vc_1k.wasm" "$ASSETS_DIR/prepare_2vc.wasm"
        echo "  Copied prepare_2vc.wasm (1k witness calculator)"
    fi

    if [ -f "$CIRCOM_BUILD/show_2vc/show_2vc_js/show_2vc.wasm" ]; then
        cp "$CIRCOM_BUILD/show_2vc/show_2vc_js/show_2vc.wasm" "$ASSETS_DIR/show_2vc.wasm"
        echo "  Copied show_2vc.wasm (witness calculator)"
    fi

    for count in 3 4; do
        if [ -f "$CIRCOM_BUILD/show_${count}vc/show_${count}vc_js/show_${count}vc.wasm" ]; then
            cp "$CIRCOM_BUILD/show_${count}vc/show_${count}vc_js/show_${count}vc.wasm" "$ASSETS_DIR/show_${count}vc.wasm"
            echo "  Copied show_${count}vc.wasm (witness calculator)"
        fi
    done

    echo "Circuit artifacts copied to $ASSETS_DIR/"
else
    echo "Warning: Circom build directory not found at $CIRCOM_BUILD"
    echo "Run 'yarn compile:all' from the circom directory first."
fi

echo "=== Build complete ==="
