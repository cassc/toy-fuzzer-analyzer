use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

use crate::types::CompileArgs;
use eyre::{Context, Result, eyre};
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{error, info};

pub fn handle_compile_command(args: CompileArgs) -> Result<()> {
    info!("Starting contract compilation and filtering process...");
    info!("Reading contract list from: {}", args.list_file.display());
    let mut failed_contracts = Vec::new();
    info!(
        "Solidity source directory: {}",
        args.solc_input_dir.display()
    );
    info!(
        "Base output directory for compiled files: {}",
        args.solc_output_dir.display()
    );

    if !args.list_file.exists() {
        return Err(eyre!("List file not found: {}", args.list_file.display()));
    }
    if !args.solc_input_dir.is_dir() {
        return Err(eyre!(
            "Solidity source directory not found or is not a directory: {}",
            args.solc_input_dir.display()
        ));
    }

    fs::create_dir_all(&args.solc_output_dir).wrap_err_with(|| {
        format!(
            "Failed to create base output directory: {}",
            args.solc_output_dir.display()
        )
    })?;

    let file = File::open(&args.list_file)
        .wrap_err_with(|| format!("Failed to open list file: {}", args.list_file.display()))?;
    let reader = BufReader::new(file);

    // Count total lines first for progress bar
    let total_lines = reader.lines().count();
    let file = File::open(&args.list_file)?;
    let reader = BufReader::new(file);

    let pb = ProgressBar::new(total_lines as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta})\n{msg}",
        )
        .unwrap()
        .progress_chars("█▓▒░ "),
    );
    pb.set_message("Starting compilation...");

    for (line_number, line_result) in reader.lines().enumerate() {
        pb.inc(1);
        let line = line_result.wrap_err_with(|| {
            format!(
                "Failed to read line {} from {}",
                line_number + 1,
                args.list_file.display()
            )
        })?;
        let line_trimmed = line.trim();

        if line_trimmed.is_empty() || line_trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line_trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            info!(
                "Warning: Skipping malformed line {} in {}: '{}'",
                line_number + 1,
                args.list_file.display(),
                line
            );
            continue;
        }

        let sol_filename_base = parts[0];
        let main_contract_name = parts[1];
        let compiler_version = parts.get(2).map(|s| s.trim().to_owned());

        let sol_file_path = args
            .solc_input_dir
            .join(format!("{}.sol", sol_filename_base));
        if !sol_file_path.exists() {
            info!(
                "Warning: Solidity file {} not found for entry '{}'. Skipping.",
                sol_file_path.display(),
                line
            );
            continue;
        }

        let specific_output_dir = args.solc_output_dir.join(sol_filename_base);

        pb.set_message(format!(
            "Processing {} (Main Contract: {}) with Compiler: {:?}",
            sol_filename_base, main_contract_name, compiler_version
        ));

        // Ensure the specific output directory for this contract exists
        fs::create_dir_all(&specific_output_dir).wrap_err_with(|| {
            format!(
                "Failed to create specific output directory: {}",
                specific_output_dir.display()
            )
        })?;

        let sol_file_path_str = sol_file_path.to_string_lossy();
        let specific_output_dir_str = specific_output_dir.to_string_lossy();
        // Run solc
        let solc_args = [
            "--bin",
            "--bin-runtime",
            "--abi",
            "--overwrite",
            "--allow-paths",
            ".",
            sol_file_path_str.as_ref(),
            "-o",
            specific_output_dir_str.as_ref(),
        ];

        info!("  Compiling with: solc {}", solc_args.join(" "));
        let solc_binary: String = match (&args.solc_binary, compiler_version){
            (Some(solc_binary), _) => solc_binary.to_string_lossy().into_owned(),
            (None, Some(ref version)) => {
                format!("~/.solc-select/artificats/solc-{}/solc-{}", version, version)
            },
            _ => "solc".into()
        };
        let mut command = Command::new("timeout");
        command
            .arg(format!("{}s", args.solc_timeout_seconds))
            .arg(&solc_binary)
            .args(solc_args)
            .stdout(Stdio::null()) // Use piped might block the thread if we don't process the output
            .stderr(Stdio::null());

        info!("  Running with timeout: {:?}", command);
        let solc_status = command
            .status() // Use status() for simple success/failure, or output() to capture
            .wrap_err_with(|| {
                format!(
                    "Failed to execute solc ({}) with timeout. ",
                    solc_binary
                )
            })?;

        let mut compilation_success = solc_status.success();

        // Verify output files exist
        if compilation_success {
            let abi_path = specific_output_dir.join(format!("{}.abi", main_contract_name));
            let bin_path = specific_output_dir.join(format!("{}.bin", main_contract_name));
            let bin_runtime_path =
                specific_output_dir.join(format!("{}.bin-runtime", main_contract_name));

            compilation_success =
                abi_path.exists() && bin_path.exists() && bin_runtime_path.exists();

            if !compilation_success {
                info!("  ERROR: Output files missing for {}", sol_filename_base);
            }
        }

        if !compilation_success {
            info!(
                "  ERROR: Solc compilation failed for {} with status: {}",
                sol_filename_base, solc_status
            );
            failed_contracts.push(sol_filename_base.to_string());
            continue;
        }
        info!("  Compilation successful for {}.", sol_filename_base);

        // Generate PTX files if enabled
        if args.generate_ptx {
            info!("  Generating PTX files for {}...", sol_filename_base);

            let bin_path = specific_output_dir.join(format!("{}.bin", main_contract_name));
            let bytecode_ll = specific_output_dir.join("bytecode.ll");
            let kernel_bc = specific_output_dir.join("kernel.bc");
            let kernel_ll = specific_output_dir.join("kernel.ll");
            let kernel_ptx = specific_output_dir.join("kernel.ptx");

            // Step 1: Generate bytecode.ll
            let status = Command::new("ptxsema")
                .arg(bin_path)
                .arg("-o")
                .arg(&bytecode_ll)
                .arg("--hex")
                .arg("--dump")
                .status()
                .wrap_err("Failed to run ptxsema")?;

            if !status.success() {
                error!("  ptxsema failed for {}", sol_filename_base);
                continue;
            }

            // Step 2: Link with runtime
            let status = Command::new("llvm-link")
                .arg("rt.o.bc")
                .arg(&bytecode_ll)
                .arg("-o")
                .arg(&kernel_bc)
                .status()
                .wrap_err("Failed to run llvm-link")?;

            if !status.success() {
                error!("  llvm-link failed for {}", sol_filename_base);
                failed_contracts.push(sol_filename_base.to_string());
                continue;
            }

            // Step 3: Disassemble to human-readable LLVM IR
            let status = Command::new("llvm-dis")
                .arg(&kernel_bc)
                .arg("-o")
                .arg(&kernel_ll)
                .status()
                .wrap_err("Failed to run llvm-dis")?;

            if !status.success() {
                error!("  llvm-dis failed for {}", sol_filename_base);
                failed_contracts.push(sol_filename_base.to_string());
                continue;
            }

            // Step 4: Generate PTX
            let status = Command::new("llc-16")
                .arg("-mcpu=sm_86")
                .arg(&kernel_bc)
                .arg("-o")
                .arg(&kernel_ptx)
                .status()
                .wrap_err("Failed to run llc-16")?;

            if !status.success() {
                error!("  llc-16 failed for {}", sol_filename_base);
                failed_contracts.push(sol_filename_base.to_string());
                continue;
            }

            info!("  PTX generation complete for {}", sol_filename_base);
        }

        let entries = fs::read_dir(&specific_output_dir).wrap_err_with(|| {
            format!(
                "Failed to read output directory: {}",
                specific_output_dir.display()
            )
        })?;

        let mut kept_count = 0;
        let mut removed_count = 0;
        for entry_result in entries {
            let entry = entry_result.wrap_err("Failed to read directory entry")?;
            let file_path = entry.path();
            if file_path.is_file() {
                let filename_osstr = entry.file_name();
                let filename_str = filename_osstr.to_string_lossy();
                let file_prefix_to_keep = format!("{}.", main_contract_name);

                if filename_str.starts_with(&file_prefix_to_keep) || filename_str.ends_with(".ptx")
                {
                    info!("    Keeping: {}", filename_str);
                    kept_count += 1;
                } else {
                    info!("    Removing: {}", filename_str);
                    fs::remove_file(&file_path).wrap_err_with(|| {
                        format!("Failed to remove file: {}", file_path.display())
                    })?;
                    removed_count += 1;
                }
            }
        }
        info!(
            "  Cleanup complete for {}. Kept {} files, removed {} files.",
            specific_output_dir.display(),
            kept_count,
            removed_count
        );
    }

    info!("\nAll contract processing finished.");

    if !failed_contracts.is_empty() {
        info!("\nFailed to compile {} contracts:", failed_contracts.len());
        for contract in failed_contracts {
            info!("  - {}", contract);
        }
    } else {
        info!("\nAll contracts compiled successfully.");
    }

    Ok(())
}
