use clap::Parser;
use compile::handle_compile_command;
use eyre::Result;
use plot::handle_plot_command;
use run::handle_run_command;
use std::env;
use tracing::{Level, info};
use tracing_subscriber::{FmtSubscriber, prelude::*};
use types::{Cli, Commands};

mod compile;
mod plot;
mod run;
mod types;

fn main() -> Result<()> {
    // Create log file
    let log_level = match env::var("LOG_LEVEL").unwrap_or_default().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let file_appender = tracing_appender::rolling::never(
        "/tmp/logs",
        format!(
            "mau-analyzer-{}.log",
            chrono::Local::now().format("%Y-%m-%d")
        ),
    );
    let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_file(true)
        .with_line_number(true)
        .with_writer(non_blocking_appender)
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting default tracing subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            info!("Executing 'run' command...");
            handle_run_command(args)?;
        }
        Commands::Plot(args) => {
            info!("Executing 'plot' command...");
            handle_plot_command(args)?;
        }
        Commands::Compile(args) => {
            info!("Executing 'compile' command...");
            handle_compile_command(args)?;
        }
    }

    Ok(())
}
