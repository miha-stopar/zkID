fn main() {
    // Construct absolute path to circuits using CARGO_MANIFEST_DIR
    // This ensures the path resolves correctly regardless of working directory
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circuits_dir = std::path::PathBuf::from(&manifest_dir)
        .parent() // Go up from ecdsa-spartan2/ to wallet-unit-poc/
        .expect("Failed to get parent directory")
        .join("circom/build/cpp");

    // Emit cfg flags for each JWT circuit size variant that has been compiled.
    // The witness!() macro in prepare_circuit.rs uses these flags to conditionally
    // include the witness-generation function for each compiled size.
    println!("cargo::rustc-check-cfg=cfg(has_circuit_base)");
    let base_jwt_cpp_file = circuits_dir.join("jwt.cpp");
    if base_jwt_cpp_file.exists() {
        println!("cargo:rustc-cfg=has_circuit_base");
        println!("cargo:warning=Found compiled circuit: jwt.cpp — enabling base JWT support");
    }

    for size in ["1k", "2k", "4k", "8k"] {
        // Declare the cfg key so rustc doesn't warn about unknown cfg names.
        println!("cargo::rustc-check-cfg=cfg(has_circuit_{})", size);
        println!(
            "cargo::rustc-check-cfg=cfg(has_circuit_prepare_2vc_{})",
            size
        );

        let cpp_file = circuits_dir.join(format!("jwt_{}.cpp", size));
        if cpp_file.exists() {
            println!("cargo:rustc-cfg=has_circuit_{}", size);
            println!(
                "cargo:warning=Found compiled circuit: jwt_{}.cpp — enabling size '{}' support",
                size, size
            );
        }

        let prepare_2vc_cpp_file = circuits_dir.join(format!("prepare_2vc_{}.cpp", size));
        if prepare_2vc_cpp_file.exists() {
            println!("cargo:rustc-cfg=has_circuit_prepare_2vc_{}", size);
            println!(
                "cargo:warning=Found compiled circuit: prepare_2vc_{}.cpp — enabling 2VC size '{}' support",
                size, size
            );
        }
    }

    println!("cargo::rustc-check-cfg=cfg(has_circuit_show_2vc)");
    println!("cargo::rustc-check-cfg=cfg(has_circuit_show_3vc)");
    println!("cargo::rustc-check-cfg=cfg(has_circuit_show_4vc)");
    println!("cargo::rustc-check-cfg=cfg(has_circuit_show)");
    let show_cpp_file = circuits_dir.join("show.cpp");
    if show_cpp_file.exists() {
        println!("cargo:rustc-cfg=has_circuit_show");
        println!("cargo:warning=Found compiled circuit: show.cpp — enabling Show support");
    }

    let show_2vc_cpp_file = circuits_dir.join("show_2vc.cpp");
    if show_2vc_cpp_file.exists() {
        println!("cargo:rustc-cfg=has_circuit_show_2vc");
        println!("cargo:warning=Found compiled circuit: show_2vc.cpp — enabling 2VC Show support");
    }

    for count in [3, 4] {
        let show_multi_cpp_file = circuits_dir.join(format!("show_{}vc.cpp", count));
        if show_multi_cpp_file.exists() {
            println!("cargo:rustc-cfg=has_circuit_show_{}vc", count);
            println!(
                "cargo:warning=Found compiled circuit: show_{}vc.cpp — enabling {}VC Show support",
                count, count
            );
        }
    }

    // Only run witnesscalc build when the native-witness feature is enabled.
    // WASM builds use JavaScript witness generation instead.
    #[cfg(feature = "native-witness")]
    {
        use std::path::Path;
        let circuits_path = circuits_dir.to_str().unwrap();

        // Check for pre-built witnesscalc cache from build_pod.sh
        if let Ok(witnesscalc_cache) = std::env::var("WITNESSCALC_PREBUILD_CACHE") {
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let target = std::env::var("TARGET").unwrap_or_default();

            // Only apply for iOS targets
            match target.as_str() {
                "aarch64-apple-ios-sim" | "aarch64-apple-ios" | "x86_64-apple-ios" => {
                    let cache_src = Path::new(&witnesscalc_cache);
                    let target_witnesscalc = Path::new(&out_dir).join("witnesscalc");

                    // Symlink entire witnesscalc directory if cache exists and target doesn't
                    if cache_src.exists() && !target_witnesscalc.exists() {
                        #[cfg(unix)]
                        {
                            println!(
                                "cargo:warning=Using cached witnesscalc from: {}",
                                cache_src.display()
                            );
                            std::os::unix::fs::symlink(&cache_src, &target_witnesscalc).ok();
                        }
                    }
                }
                _ => {}
            }
        }

        witnesscalc_adapter::build_and_link(circuits_path);
    }
}
