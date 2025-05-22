use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

use crate::types::CompileArgs;
use eyre::{Context, Result, eyre};

pub fn handle_compile_command(args: CompileArgs) -> Result<()> {
    println!("Starting contract compilation and filtering process...");
    println!("Reading contract list from: {}", args.list_file.display());
    println!(
        "Solidity source directory: {}",
        args.solc_input_dir.display()
    );
    println!(
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

    for (line_number, line_result) in reader.lines().enumerate() {
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
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            eprintln!(
                "Warning: Skipping malformed line {} in {}: '{}'",
                line_number + 1,
                args.list_file.display(),
                line
            );
            continue;
        }

        let sol_filename_base = parts[0];
        let main_contract_name = parts[1];

        let sol_file_path = args
            .solc_input_dir
            .join(format!("{}.sol", sol_filename_base));
        if !sol_file_path.exists() {
            eprintln!(
                "Warning: Solidity file {} not found for entry '{}'. Skipping.",
                sol_file_path.display(),
                line
            );
            continue;
        }

        let specific_output_dir = args.solc_output_dir.join(sol_filename_base);

        println!(
            "\nProcessing {} (Main Contract: {})...",
            sol_filename_base, main_contract_name
        );

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

        println!("  Compiling with: solc {}", solc_args.join(" "));
        let mut command = Command::new("timeout");
        command
            .arg(format!("{}s", args.solc_timeout_seconds))
            .arg("solc")
            .args(solc_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        println!("  Running with timeout: {:?}", command);
        let solc_status = command
            .status() // Use status() for simple success/failure, or output() to capture
            .wrap_err("Failed to execute solc with timeout. Is timeout and solc installed and in PATH?")?;

        if !solc_status.success() {
            eprintln!(
                "  ERROR: Solc compilation failed for {} with status: {}. Check solc output if any.",
                sol_filename_base, solc_status
            );
            continue;
        }
        println!("  Compilation successful for {}.", sol_filename_base);

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

                if filename_str.starts_with(main_contract_name) {
                    println!("    Keeping: {}", filename_str);
                    kept_count += 1;
                } else {
                    println!("    Removing: {}", filename_str);
                    fs::remove_file(&file_path).wrap_err_with(|| {
                        format!("Failed to remove file: {}", file_path.display())
                    })?;
                    removed_count += 1;
                }
            }
        }
        println!(
            "  Cleanup complete for {}. Kept {} files, removed {} files.",
            specific_output_dir.display(),
            kept_count,
            removed_count
        );
    }

    println!("\nAll contract processing finished.");
    Ok(())
}
