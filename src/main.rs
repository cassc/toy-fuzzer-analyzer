use clap::{Parser, Subcommand};
use csv::{Reader, Writer}; // Added Reader
use eyre::{Result, WrapErr, eyre};
use glob::glob;
use plotters::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize}; // Added Deserialize
use std::collections::{BTreeMap, HashMap};
use std::fs::{self};
// use std::io::Read; // Removed, not used
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::{self, sleep}; // Removed, sleep in run_program_with_timeout is removed
use std::time::Duration; // Still used for Duration::from_secs if any other sleep is needed, but not here

#[derive(Parser, Debug)]
#[command(author, version, about = "Analyzes fuzzer output or plots existing data", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the fuzzer, analyze output, write CSVs, and plot results
    Run(RunArgs),
    /// Plot results from existing CSV data in the output directory
    Plot(PlotArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Path to the fuzzer executable
    #[arg(short, long, value_name = "FILE", default_value = "./mau-ityfuzz")]
    fuzzer_path: PathBuf,

    /// Base directory containing benchmark contract directories (e.g., b1)
    #[arg(short, long, value_name = "DIR")]
    benchmark_base_dir: PathBuf,

    /// Output directory for CSV files and the plot
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    output_dir: PathBuf,

    /// Timeout in seconds for running the fuzzer on each contract
    #[arg(long, value_name = "SECONDS", default_value_t = 15)]
    fuzz_timeout_seconds: u64,
}

#[derive(Parser, Debug)]
struct PlotArgs {
    /// Directory containing the CSV data files and where the plot will be saved
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    output_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)] // Added Deserialize
struct StatsEntry {
    instructions_covered: u64,
    branches_covered: u64,
    time_taken_nanos: u64,
}

fn run_program_with_timeout(
    program_path: &Path,
    args: &[&str],
    timeout_seconds: u64,
) -> Result<String> {
    println!(
        "Running program {} with args {:?} and timeout {}s",
        program_path.display(),
        args,
        timeout_seconds
    );

    let absolute_path = fs::canonicalize(program_path).wrap_err_with(|| {
        format!(
            "Program executable not found or path invalid: {}",
            program_path.display()
        )
    })?;

    let program_path_str = absolute_path.to_str().ok_or_else(|| {
        eyre!(
            "Program path is not valid UTF-8: {}",
            absolute_path.display()
        )
    })?;

    let timeout_str = timeout_seconds.to_string();

    let child = Command::new("timeout")
        .args([&timeout_str, program_path_str])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // Capture stderr
        .spawn()
        .wrap_err_with(|| format!("Failed to start program {}", program_path.display()))?;

    // The `sleep` call that was here is removed. `timeout` command handles the timeout.
    sleep(Duration::from_secs(timeout_seconds));
    // `child.wait_with_output()` will block until the `timeout` command itself finishes.

    let output = child.wait_with_output()?;
    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        if !stderr_str.is_empty() {
            eprintln!(
                "Stderr from running {}:\n{}",
                program_path.display(),
                stderr_str.trim()
            );
        }
        if output.status.code() == Some(124) {
            println!("Program {} timed out.", program_path.display());
            // For timeout, we still want to process any stdout produced, so we don't return Err here.
        } else {
            eprintln!(
                "Program {} (or timeout command) exited with status {}.",
                program_path.display(),
                output.status
            );
            // Depending on strictness, one might return an Err here.
            // For now, we allow processing of stdout even if the process failed non-timeout.
        }
    }

    Ok(stdout_str)
}

fn parse_log(log_content: &str, contract_id: &str) -> Result<Vec<StatsEntry>> {
    let mut entries = Vec::new();
    let began_at_re =
        Regex::new(r"Began at (\d+)").wrap_err("Failed to compile 'Began at' regex")?;
    let stats_re =
        Regex::new(r"Instruction Covered: (\d+); Branch Covered: (\d+) Timestamp Nanos: (\d+)")
            .wrap_err("Failed to compile 'Stats' regex")?;

    let mut began_at_nanos: Option<u64> = None;

    for line in log_content.lines() {
        if began_at_nanos.is_none() {
            if let Some(caps) = began_at_re.captures(line) {
                began_at_nanos = Some(caps[1].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse 'Began at' timestamp: {}", &caps[1])
                })?);
            }
        }

        if let Some(current_began_at) = began_at_nanos {
            if let Some(caps) = stats_re.captures(line) {
                let instructions_covered = caps[1].parse::<u64>().wrap_err_with(|| {
                    format!("Failed to parse instructions_covered: {}", &caps[1])
                })?;
                let branches_covered = caps[2]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse branches_covered: {}", &caps[2]))?;
                let timestamp_nanos: u64 = caps[3]
                    .parse::<u64>()
                    .wrap_err_with(|| format!("Failed to parse timestamp_nanos: {}", &caps[3]))?;

                if timestamp_nanos >= current_began_at {
                    let time_taken_nanos = timestamp_nanos - current_began_at;
                    entries.push(StatsEntry {
                        instructions_covered,
                        branches_covered,
                        time_taken_nanos,
                    });
                }
            }
        }
    }

    if began_at_nanos.is_none() && !log_content.trim().is_empty() {
        // Check if log_content is not empty before erroring for missing "Began at"
        let non_empty_meaningful_lines = log_content.lines().any(|l| stats_re.is_match(l));
        if non_empty_meaningful_lines {
            return Err(eyre!(
                "No 'Began at' timestamp found in log for {} despite other stat lines being present.",
                contract_id
            ));
        } else if !log_content.trim().is_empty() {
            println!(
                "Warning: No 'Began at' timestamp found in log for {}, and no stat lines. Log: '{}'",
                contract_id,
                log_content.chars().take(100).collect::<String>()
            ); // Print only first 100 chars
        }
    }

    entries.sort_by_key(|e| e.time_taken_nanos);
    entries.dedup_by_key(|e| e.time_taken_nanos);

    Ok(entries)
}

fn write_csv(contract_id: &str, entries: &[StatsEntry], output_path_base: &Path) -> Result<()> {
    let csv_path = output_path_base.join(format!("{}.instructions.stats.csv", contract_id));
    let mut wtr = Writer::from_path(&csv_path)
        .wrap_err_with(|| format!("Failed to create CSV writer for {}", csv_path.display()))?;
    wtr.write_record([
        "instructions_covered",
        "branches_covered",
        "time_taken_nanos",
    ])
    .wrap_err("Failed to write CSV header")?;
    for entry in entries {
        wtr.serialize(entry)
            .wrap_err("Failed to serialize entry to CSV")?;
    }
    wtr.flush().wrap_err("Failed to flush CSV writer")?;
    Ok(())
}

fn read_stats_from_csv(csv_path: &Path) -> Result<Vec<StatsEntry>> {
    let mut rdr = Reader::from_path(csv_path)
        .wrap_err_with(|| format!("Failed to open CSV file: {}", csv_path.display()))?;
    let mut entries = Vec::new();
    for result in rdr.deserialize() {
        let entry: StatsEntry = result.wrap_err_with(|| {
            format!("Failed to deserialize record from {}", csv_path.display())
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn aggregate_and_plot_data(
    all_contract_stats: &HashMap<String, Vec<StatsEntry>>,
    plot_output_dir: &Path, // Renamed for clarity, this is where the plot is saved
) -> Result<()> {
    if all_contract_stats.is_empty() {
        println!("No data to plot.");
        return Ok(());
    }

    let mut aggregated_instructions_over_time: BTreeMap<u64, u64> = BTreeMap::new();
    let mut all_timestamps: Vec<u64> = Vec::new();

    for stats_vec in all_contract_stats.values() {
        for entry in stats_vec {
            all_timestamps.push(entry.time_taken_nanos);
        }
    }
    all_timestamps.sort_unstable();
    all_timestamps.dedup();

    if all_timestamps.is_empty() {
        println!("No timestamps found in data. Skipping plot.");
        return Ok(());
    }

    for &ts_nano in &all_timestamps {
        let mut current_total_instructions = 0;
        for stats_vec in all_contract_stats.values() {
            let latest_instr_for_contract = stats_vec
                .iter()
                .filter(|e| e.time_taken_nanos <= ts_nano)
                .max_by_key(|e| e.time_taken_nanos)
                .map_or(0, |e| e.instructions_covered);
            current_total_instructions += latest_instr_for_contract;
        }
        aggregated_instructions_over_time.insert(ts_nano, current_total_instructions);
    }

    let plot_data: Vec<(f64, f64)> = aggregated_instructions_over_time
        .into_iter()
        .map(|(time_ns, instr_count)| {
            let time_minutes = time_ns as f64 / (1_000_000_000.0 * 60.0);
            let instructions_k = instr_count as f64 / 1000.0;
            (time_minutes, instructions_k)
        })
        .collect();

    if plot_data.is_empty() {
        println!("Aggregated plot data is empty. Skipping plot generation.");
        return Ok(());
    }

    let plot_path = plot_output_dir.join("overall_instructions_plot.png");

    let root_area = BitMapBackend::new(&plot_path, (1024, 768)).into_drawing_area();
    root_area
        .fill(&WHITE)
        .wrap_err("Failed to fill plot background")?;

    let max_time_minutes = plot_data.iter().map(|(t, _)| *t).fold(0.0_f64, f64::max) * 1.1;
    let max_instr_k = plot_data.iter().map(|(_, i)| *i).fold(0.0_f64, f64::max) * 1.1;

    let x_axis_max = if max_time_minutes > 0.0 {
        max_time_minutes
    } else {
        1.0
    };
    let y_axis_max = if max_instr_k > 0.0 { max_instr_k } else { 1.0 };

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            "Overall Instructions Covered vs. Time",
            ("sans-serif", 30).into_font(),
        )
        .margin(10)
        .x_label_area_size(40)
        .y_label_area_size(50)
        .build_cartesian_2d(0.0..x_axis_max, 0.0..y_axis_max)
        .wrap_err("Failed to build chart")?;

    chart
        .configure_mesh()
        .x_desc("Time (minutes)")
        .y_desc("Number of Instructions / 10^3")
        .draw()
        .wrap_err("Failed to draw chart mesh")?;

    chart
        .draw_series(LineSeries::new(plot_data, &RED))
        .wrap_err("Failed to draw data series on chart")?;

    root_area.present().wrap_err("Failed to present chart")?;
    println!("Plot saved to {}", plot_path.display());

    Ok(())
}

fn handle_run_command(args: RunArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir).wrap_err_with(|| {
        format!(
            "Failed to create output directory: {}",
            args.output_dir.display()
        )
    })?;

    let mut all_contract_stats: HashMap<String, Vec<StatsEntry>> = HashMap::new();

    let benchmark_glob_pattern = format!("{}/*", args.benchmark_base_dir.to_string_lossy());

    let glob_pattern_results = glob(&benchmark_glob_pattern)
        .wrap_err_with(|| format!("Invalid glob pattern: '{}'", benchmark_glob_pattern))?;

    let mut contract_dirs: Vec<PathBuf> = Vec::new();
    for entry_result in glob_pattern_results {
        let path = entry_result.wrap_err("Error processing a path from glob pattern")?;
        if path.is_dir()
            && path
                .file_name()
                .map_or(false, |name| name.to_string_lossy().starts_with("20"))
        {
            contract_dirs.push(path);
        }
    }

    if contract_dirs.is_empty() {
        return Err(eyre!(
            "No contract directories found in {} matching pattern {}/* (looking for names starting with '20')",
            args.benchmark_base_dir.display(),
            args.benchmark_base_dir.display()
        ));
    }

    println!("Found contract directories: {:?}", contract_dirs);

    for contract_dir_path in contract_dirs {
        let contract_id = contract_dir_path
            .file_name()
            .ok_or_else(|| eyre!("Could not get file name from path: {:?}", contract_dir_path))?
            .to_string_lossy()
            .into_owned();

        let contract_files_glob = format!("{}/*", contract_dir_path.to_string_lossy());
        let options = ["-t", &contract_files_glob]; // -t requires a single target, not a glob pattern for files. This might be a misunderstanding of fuzzer's -t.
        // Assuming fuzzer's -t option expects a directory or a specific file.
        // If it expects a directory, then contract_dir_path itself should be used.
        // If it expects all files in the directory, the fuzzer must support glob itself or be called per file.
        // For now, keeping original logic, but noting potential issue with `contract_files_glob` as a fuzzer arg.
        // If the fuzzer expects a directory, this should be:
        // let target_path_str = contract_dir_path.to_str().ok_or_else(...)
        // let options = ["-t", target_path_str];

        match run_program_with_timeout(&args.fuzzer_path, &options[..], args.fuzz_timeout_seconds) {
            Ok(log_content) => {
                if log_content.trim().is_empty() {
                    println!(
                        "No output from fuzzer for {}, skipping parsing (likely timeout or crash before output).",
                        contract_id
                    );
                    continue;
                }
                match parse_log(&log_content, &contract_id) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            if !log_content.trim().is_empty() {
                                // Only print if log was not empty
                                println!(
                                    "No statistical entries parsed for {}, though log was not empty. Log (first 100 chars): '{}'",
                                    contract_id,
                                    log_content.chars().take(100).collect::<String>()
                                );
                            } else {
                                println!(
                                    "No statistical entries parsed for {} (empty log).",
                                    contract_id
                                );
                            }
                        } else {
                            println!(
                                "Parsed {} entries for contract {}",
                                entries.len(),
                                contract_id
                            );
                            write_csv(&contract_id, &entries, &args.output_dir)?;
                            println!(
                                "CSV saved for {} to {}/{}.instructions.stats.csv",
                                contract_id,
                                args.output_dir.display(),
                                contract_id
                            );
                            all_contract_stats.insert(contract_id.clone(), entries);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Error parsing log for contract {}: {:?}\nLog content (first 200 chars):\n{}",
                            contract_id,
                            e,
                            log_content.chars().take(200).collect::<String>()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Error running fuzzer for contract {}: {:?}", contract_id, e);
            }
        }
    }

    if all_contract_stats.is_empty() {
        println!("No data collected from any contracts. Cannot generate aggregate plot.");
    } else {
        aggregate_and_plot_data(&all_contract_stats, &args.output_dir)?;
    }

    println!(
        "Run command complete. Outputs are in the '{}' directory.",
        args.output_dir.display()
    );
    Ok(())
}

fn handle_plot_command(args: PlotArgs) -> Result<()> {
    if !args.output_dir.exists() {
        return Err(eyre!(
            "Output directory {} does not exist. Cannot read CSV data.",
            args.output_dir.display()
        ));
    }
    if !args.output_dir.is_dir() {
        return Err(eyre!(
            "Path {} is not a directory.",
            args.output_dir.display()
        ));
    }

    let mut all_contract_stats: HashMap<String, Vec<StatsEntry>> = HashMap::new();
    let csv_glob_pattern_str = args
        .output_dir
        .join("*.instructions.stats.csv")
        .to_string_lossy()
        .into_owned();

    println!("Looking for CSV files matching: {}", csv_glob_pattern_str);

    let glob_results = glob(&csv_glob_pattern_str).wrap_err_with(|| {
        format!(
            "Invalid glob pattern for CSV files: '{}'",
            csv_glob_pattern_str
        )
    })?;

    let mut found_csv_files = false;
    for entry_result in glob_results {
        match entry_result {
            Ok(csv_path) => {
                found_csv_files = true;
                let filename = csv_path
                    .file_name()
                    .ok_or_else(|| eyre!("Could not get file name from path: {:?}", csv_path))?
                    .to_string_lossy();

                if let Some(contract_id_str) = filename.strip_suffix(".instructions.stats.csv") {
                    let contract_id = contract_id_str.to_owned();
                    println!(
                        "Reading data for contract: {} from {}",
                        contract_id,
                        csv_path.display()
                    );
                    match read_stats_from_csv(&csv_path) {
                        Ok(entries) => {
                            if entries.is_empty() {
                                println!(
                                    "No entries found in CSV for contract {}: {}",
                                    contract_id,
                                    csv_path.display()
                                );
                            } else {
                                println!(
                                    "Read {} entries for contract {} from {}",
                                    entries.len(),
                                    contract_id,
                                    csv_path.display()
                                );
                                all_contract_stats.insert(contract_id, entries);
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "Error reading or parsing CSV file {}: {:?}",
                                csv_path.display(),
                                e
                            );
                        }
                    }
                } else {
                    // This case should ideally not happen if glob pattern is specific enough
                    println!(
                        "Skipping file not matching expected pattern suffix: {}",
                        csv_path.display()
                    );
                }
            }
            Err(e) => {
                eprintln!("Error accessing file during CSV glob: {:?}", e);
            }
        }
    }

    if !found_csv_files {
        println!(
            "No CSV files found matching pattern '{}'.",
            csv_glob_pattern_str
        );
    }

    if all_contract_stats.is_empty() {
        println!("No data loaded from CSV files. Cannot generate aggregate plot.");
        return Ok(());
    }

    // The plot will be saved in args.output_dir
    // Ensure the directory exists for writing the plot (it should, as we checked earlier for reading)
    fs::create_dir_all(&args.output_dir).wrap_err_with(|| {
        format!(
            "Failed to ensure output directory for plot exists: {}",
            args.output_dir.display()
        )
    })?;

    aggregate_and_plot_data(&all_contract_stats, &args.output_dir)?;
    println!(
        "Plot command complete. Plot is in the '{}' directory.",
        args.output_dir.display()
    );

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            println!("Executing 'run' command...");
            handle_run_command(args)?;
        }
        Commands::Plot(args) => {
            println!("Executing 'plot' command...");
            handle_plot_command(args)?;
        }
    }

    Ok(())
}
