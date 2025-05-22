use clap::Parser;
use compile::handle_compile_command;
use eyre::Result;
use plot::handle_plot_command;
use run::handle_run_command;
use types::{Cli, Commands}; // Added Deserialize

mod compile;
mod plot;
mod run;
mod types;

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
        Commands::Compile(args) => {
            println!("Executing 'compile' command...");
            handle_compile_command(args)?;
        }
    }

    Ok(())
}
