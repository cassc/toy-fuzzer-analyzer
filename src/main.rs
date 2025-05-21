use clap::Parser;
use csv::Writer;
use eyre::{Result, WrapErr, eyre};
use glob::glob;
use plotters::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about = "Analyzes fuzzer output for coverage over time", long_about = None)]
struct Args {
    /// Path to the fuzzer executable
    #[arg(short, long, value_name = "FILE", default_value = "./mau-ityfuzz")]
    fuzzer_path: PathBuf,

    /// Base directory containing benchmark contract directories (e.g., b1)
    #[arg(short, long, value_name = "DIR", default_value = "b1")]
    benchmark_base_dir: PathBuf,

    /// Output directory for CSV files and the plot
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    output_dir: PathBuf,

    /// Timeout in seconds for running the fuzzer on each contract
    #[arg(short, long, value_name = "SECONDS", default_value_t = 15)]
    fuzz_timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
struct StatsEntry {
    instructions_covered: u64,
    branches_covered: u64,
    time_taken_nanos: u64,
}

fn run_program_with_timeout(
    program_path: &Path,
    args: &str,
    timeout_seconds: u64,
) -> Result<String> {
    println!(
        "Running program {} with args {:?} and timeout {}s",
        program_path.display(),
        args,
        timeout_seconds
    );

    // Canonicalize the program path
    let absolute_path = fs::canonicalize(program_path).wrap_err_with(|| {
        format!(
            "Program executable not found or path invalid: {}",
            program_path.display()
        )
    })?;

    // Spawn the program with piped stdout and stderr
    let mut child = Command::new(&absolute_path)
        .args([args])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err_with(|| format!("Failed to start program {}", program_path.display()))?;

    // Take ownership of stdout and stderr streams
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("Failed to capture stdout"))?;

    // Wait for output with a timeout
    let timeout = Duration::from_secs(timeout_seconds);

    // Sleep for the timeout duration
    println!("Waiting for {} seconds...", timeout_seconds);
    thread::sleep(timeout);

    if let Ok(None) = child.try_wait() {
        // Still running, kill it
        child.kill().wrap_err("Failed to kill program process")?;
        child
            .wait()
            .wrap_err("Failed to wait for program process after kill")?;
    }

    let mut stdout_data = Vec::new();

    stdout.read_to_end(&mut stdout_data).unwrap_or(0);

    Ok(String::from_utf8_lossy(&stdout_data).to_string())
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
        return Err(eyre!(
            "No 'Began at' timestamp found in log for {}",
            contract_id
        ));
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

fn aggregate_and_plot_data(
    all_contract_stats: &HashMap<String, Vec<StatsEntry>>,
    output_path_base: &Path, // Use output_path_base here
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

    let plot_path = output_path_base.join("overall_instructions_plot.png"); // Generate plot path here

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

fn main() -> Result<()> {
    let args = Args::parse(); // Parse command line arguments

    fs::create_dir_all(&args.output_dir).wrap_err_with(|| {
        format!(
            "Failed to create output directory: {}",
            args.output_dir.display()
        )
    })?;
    // output_path_base is now args.output_dir

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

        match run_program_with_timeout(
            &args.fuzzer_path,
            &contract_files_glob,
            args.fuzz_timeout_seconds,
        ) {
            Ok(log_content) => {
                if log_content.trim().is_empty() {
                    println!(
                        "No output from fuzzer for {}, skipping parsing (likely timeout before output).",
                        contract_id
                    );
                    continue;
                }
                match parse_log(&log_content, &contract_id) {
                    Ok(entries) => {
                        if entries.is_empty() {
                            println!(
                                "No statistical entries parsed for {}, though log was not empty. Log content:\n{}",
                                contract_id, log_content
                            );
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
                            "Error parsing log for contract {}: {:?}\nLog content:\n{}",
                            contract_id, e, log_content
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
        "Analysis complete. Outputs are in the '{}' directory.",
        args.output_dir.display()
    );
    Ok(())
}
