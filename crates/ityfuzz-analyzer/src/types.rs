use clap::{Parser, Subcommand};
// Added Reader
use serde::{Deserialize, Serialize}; // Added Deserialize
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Analyzes fuzzer output or plots existing data", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the fuzzer, analyze output, write CSVs, and plot results
    Run(RunArgs),
    /// Plot results from existing CSV data in the output directory
    Plot(PlotArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Path to the fuzzer executable
    #[arg(short, long, value_name = "FILE", default_value = "ityfuzz")]
    pub fuzzer_path: String,

    /// Additional arguments to be added before the `-t <target-contract-folder>/*` argument for ityfuzz
    #[arg(long,
          default_values_t = vec![
            "evm".to_string(),
            "--run-forever".to_string(),
            "-d".to_string(),
            "all".to_string()
          ],
          value_name = "ARGS")]
    pub fuzzer_options: Vec<String>,

    /// Base directory containing benchmark contract directories (e.g., b1)
    #[arg(short, long, value_name = "DIR")]
    pub benchmark_base_dir: PathBuf,

    /// Output directory for CSV files and the plot
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    pub output_dir: PathBuf,

    /// Timeout in seconds for running the fuzzer on each contract
    #[arg(long, value_name = "SECONDS", default_value_t = 15)]
    pub fuzz_timeout_seconds: u64,
}

#[derive(Parser, Debug)]
pub struct PlotArgs {
    /// Directory containing the CSV data files and where the plot will be saved
    #[arg(short, long, value_name = "DIR", default_value = "analysis_output")]
    pub output_dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsEntry {
    pub instructions_covered: u64,
    pub branches_covered: u64,
    // Exists in log but not used
    // pub total_instructions: u64,
    // pub total_coverages: u64,
    pub time_taken_millis: u64,
}
