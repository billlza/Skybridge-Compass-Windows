use std::num::TryFromIntError;
use std::process::ExitCode;

fn main() -> Result<ExitCode, TryFromIntError> {
    let args = std::env::args().skip(1);
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let code = skybridge_core::cli::run(args, &mut stdout, &mut stderr);
    Ok(ExitCode::from(u8::try_from(code)?))
}
