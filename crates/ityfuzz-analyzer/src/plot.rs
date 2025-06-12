use crate::types::{PlotArgs, StatsEntry};
use csv::Reader; // Added Reader
use eyre::{Result, WrapErr, eyre};
use glob::glob;
use plotters::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self};
use std::path::Path;
use tracing::info;
// Added Deserialize

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

pub fn aggregate_and_plot_data(
    all_contract_stats: &HashMap<String, Vec<StatsEntry>>,
    plot_output_dir: &Path,
    title_prefix: Option<String>,
) -> Result<()> {
    if all_contract_stats.is_empty() {
        info!("No data to plot.");
        return Ok(());
    }

    let title_prefix = title_prefix.unwrap_or_else(|| {
        plot_output_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    });

    let mut aggregated_instructions_over_time: BTreeMap<u64, u64> = BTreeMap::new();
    let mut all_timestamps: Vec<u64> = Vec::new();

    for stats_vec in all_contract_stats.values() {
        for entry in stats_vec {
            all_timestamps.push(entry.time_taken_millis);
        }
    }
    all_timestamps.sort_unstable();
    all_timestamps.dedup();

    if all_timestamps.is_empty() {
        info!("No timestamps found in data. Skipping plot.");
        return Ok(());
    }

    for &ts_nano in &all_timestamps {
        let mut current_total_instructions = 0;
        for stats_vec in all_contract_stats.values() {
            let latest_instr_for_contract = stats_vec
                .iter()
                .filter(|e| e.time_taken_millis <= ts_nano)
                .max_by_key(|e| e.time_taken_millis)
                .map_or(0, |e| e.instructions_covered);
            current_total_instructions += latest_instr_for_contract;
        }
        aggregated_instructions_over_time.insert(ts_nano, current_total_instructions);
    }

    let plot_data: Vec<(f64, f64)> = aggregated_instructions_over_time
        .into_iter()
        .map(|(time_ms, instr_count)| {
            let time_seconds = time_ms as f64 / 1_000.0;
            let instructions_k = instr_count as f64 / 1000.0;
            (time_seconds, instructions_k)
        })
        .collect();

    if plot_data.is_empty() {
        info!("Aggregated plot data is empty. Skipping plot generation.");
        return Ok(());
    }

    // store the overall csv stats
    let overall_stats_csv_path =
        plot_output_dir.join(format!("{}_overall_instructions_stats.csv", title_prefix));
    let mut wtr = csv::Writer::from_path(&overall_stats_csv_path).wrap_err_with(|| {
        format!(
            "Failed to create CSV writer for {}",
            overall_stats_csv_path.display()
        )
    })?;
    wtr.write_record(["time_seconds", "instructions(k)"])
        .wrap_err("Failed to write CSV header")?;

    for (time_seconds, instructions_k) in &plot_data {
        wtr.write_record([time_seconds.to_string(), instructions_k.to_string()])
            .wrap_err("Failed to write CSV record")?;
    }

    wtr.flush().wrap_err("Failed to flush CSV writer")?;

    let plot_path = plot_output_dir.join(format!("{}_overall_instructions_plot.png", title_prefix));

    let root_area = BitMapBackend::new(&plot_path, (1024, 768)).into_drawing_area();
    root_area
        .fill(&WHITE)
        .wrap_err("Failed to fill plot background")?;

    let max_time_seconds = plot_data.iter().map(|(t, _)| *t).fold(0.0_f64, f64::max) * 1.1;
    let max_instr_k = plot_data.iter().map(|(_, i)| *i).fold(0.0_f64, f64::max) * 1.1;

    let x_axis_max = if max_time_seconds > 0.0 {
        max_time_seconds
    } else {
        1.0
    };
    let y_axis_max = if max_instr_k > 0.0 { max_instr_k } else { 1.0 };

    let mut chart = ChartBuilder::on(&root_area)
        .caption(
            format!("{} Overall Instructions Covered vs. Time", title_prefix),
            ("sans-serif", 30).into_font(),
        )
        .margin(10)
        .x_label_area_size(40)
        .y_label_area_size(50)
        .build_cartesian_2d(0.0..x_axis_max, 0.0..y_axis_max)
        .wrap_err("Failed to build chart")?;

    chart
        .configure_mesh()
        .x_desc("Time (seconds)")
        .y_desc("Number of Instructions / 10^3")
        .draw()
        .wrap_err("Failed to draw chart mesh")?;

    chart
        .draw_series(LineSeries::new(plot_data, &RED))
        .wrap_err("Failed to draw data series on chart")?;

    root_area.present().wrap_err("Failed to present chart")?;
    info!("Plot saved to {}", plot_path.display());

    Ok(())
}

pub fn handle_plot_command(args: PlotArgs) -> Result<()> {
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

    info!("Looking for CSV files matching: {}", csv_glob_pattern_str);

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
                    info!(
                        "Reading data for contract: {} from {}",
                        contract_id,
                        csv_path.display()
                    );
                    match read_stats_from_csv(&csv_path) {
                        Ok(entries) => {
                            if entries.is_empty() {
                                info!(
                                    "No entries found in CSV for contract {}: {}",
                                    contract_id,
                                    csv_path.display()
                                );
                            } else {
                                info!(
                                    "Read {} entries for contract {} from {}",
                                    entries.len(),
                                    contract_id,
                                    csv_path.display()
                                );
                                all_contract_stats.insert(contract_id, entries);
                            }
                        }
                        Err(e) => {
                            info!(
                                "Error reading or parsing CSV file {}: {:?}",
                                csv_path.display(),
                                e
                            );
                        }
                    }
                } else {
                    // This case should ideally not happen if glob pattern is specific enough
                    info!(
                        "Skipping file not matching expected pattern suffix: {}",
                        csv_path.display()
                    );
                }
            }
            Err(e) => {
                info!("Error accessing file during CSV glob: {:?}", e);
            }
        }
    }

    if !found_csv_files {
        info!(
            "No CSV files found matching pattern '{}'.",
            csv_glob_pattern_str
        );
    }

    if all_contract_stats.is_empty() {
        info!("No data loaded from CSV files. Cannot generate aggregate plot.");
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

    aggregate_and_plot_data(&all_contract_stats, &args.output_dir, None)?;
    info!(
        "Plot command complete. Plot is in the '{}' directory.",
        args.output_dir.display()
    );

    Ok(())
}
