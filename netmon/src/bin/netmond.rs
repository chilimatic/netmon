use std::process::ExitCode;

fn main() -> ExitCode {
    match netmon::run_daemon() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("netmond: {e:#}");
            // EX_CONFIG: the unit does not restart on it.
            if e.downcast_ref::<netmon::RulesFileError>().is_some() { ExitCode::from(78) } else { ExitCode::FAILURE }
        }
    }
}
