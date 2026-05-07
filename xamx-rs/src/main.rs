use std::path::PathBuf;

use xamx_rs::cli::run;

fn main() {
    let args = std::env::args_os().skip(1).map(PathBuf::from).collect::<Vec<_>>();
    if let Err(err) = run(&args) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
