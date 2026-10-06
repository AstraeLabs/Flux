#[cfg(feature = "cli")]
fn main() -> std::process::ExitCode {
    use clap::Parser;
    use flux::cli::{Args, run};

    if std::env::args().nth(1).as_deref() == Some("--daemon") {
        #[cfg(feature = "cenc")]
        return flux::cli::run_daemon();
        #[cfg(not(feature = "cenc"))]
        {
            eprintln!("flux: --daemon requires this build's `cenc` feature (decrypt-only mode)");
            return std::process::ExitCode::FAILURE;
        }
    }

    let args = Args::parse();
    match run(args) {
        Ok((container, format)) => {
            eprintln!("flux: {container} → {format}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("flux: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("flux: build with `--features cli` to use the command-line packager");
}
