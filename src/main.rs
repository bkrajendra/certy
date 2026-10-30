use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

mod install;
mod logger;

use install::{
    detect_os, has_elevated_privileges, install_certificate, is_cert_already_trusted,
    verify_install, OsFamily,
};
use logger::{log, banner, Level};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the CA certificate PEM file (default: ca-cert.pem next to the binary)
    #[arg(short = 'c', long = "cert", value_name = "FILE")]
    cert: Option<PathBuf>,

    /// Skip the confirmation prompt and proceed automatically
    #[arg(short = 'y', long = "yes")]
    yes: bool,

    /// Force import even if the file does not look like a PEM certificate
    #[arg(long = "force")]
    force: bool,

    /// Enable verbose output
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

/// Create a styled indeterminate spinner.
fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner} {msg}").unwrap());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_message(msg.to_string());
    pb
}

/// Ask the user a yes/no question.
fn confirm(prompt: &str) -> io::Result<bool> {
    print!("{} {} [y/N]: ", "?".yellow().bold(), prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Prompt the user to enter a file path.
fn prompt_path(prompt: &str) -> io::Result<PathBuf> {
    print!("{} {}: ", "?".yellow().bold(), prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(PathBuf::from(input.trim()))
}

/// Resolve the certificate path: explicit --cert, default next to binary,
/// or interactively ask the user for a path.
fn resolve_cert_path(args_cert: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(p) = args_cert {
        return Ok(p);
    }

    // Default: ca-cert.pem next to the binary
    let default = install::binary_dir()?.join("ca-cert.pem");
    if default.exists() {
        return Ok(default);
    }

    // Fallback: ca-cert.pem in current working directory
    let cwd_default = std::env::current_dir().unwrap_or_default().join("ca-cert.pem");
    if cwd_default.exists() {
        return Ok(cwd_default);
    }

    // Not found — ask the user, unless running non-interactively (CI / automated testing).
    if !io::stdin().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "ca-cert.pem not found next to the binary or in the current directory, \
             and stdin is not a TTY (non-interactive). Place ca-cert.pem next to the binary \
             or pass --cert /path/to/ca-cert.pem.",
        ));
    }
    log(Level::Warn, "ca-cert.pem not found next to the binary or in the current directory.");
    loop {
        let path = prompt_path("Enter path to CA certificate PEM file")?;
        if path.exists() {
            return Ok(path);
        }
        log(Level::Error, &format!("File not found: {}", path.display()));
        log(Level::Info, "Please enter a valid path, or press Ctrl+C to abort.");
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    banner();

    // ───── 1. Detect operating system ─────
    let pb = spinner("Detecting operating system…");
    let os = detect_os();
    let os_label = match os {
        OsFamily::Windows => "Microsoft Windows",
        OsFamily::Linux => "Linux",
        OsFamily::MacOS => "Apple macOS",
    };
    pb.finish_and_clear();
    log(Level::Info, &format!("Operating system: {}", os_label.bold()));

    // ───── 2. Locate the certificate ─────
    let pb = spinner("Locating certificate file…");
    let cert_path = match resolve_cert_path(args.cert.clone()) {
        Ok(p) => p,
        Err(e) => {
            log(Level::Error, &format!("Could not resolve certificate path: {}", e));
            std::process::exit(1);
        }
    };
    pb.finish_and_clear();

    if !cert_path.exists() {
        log(Level::Error, &format!("Certificate file not found: {}", cert_path.display()));
        log(Level::Info, "Expected: ca-cert.pem in the same folder as the binary.");
        log(Level::Info, "Use --cert /path/to/ca-cert.pem to specify another location.");
        std::process::exit(1);
    }

    let size = fs::metadata(&cert_path)
        .map(|m| m.len())
        .unwrap_or(0);
    log(Level::Success, &format!(
        "Found: {}  ({} bytes)",
        cert_path.display(),
        size
    ));

    // ───── 3. Inspect the certificate ─────
    let data = match fs::read(&cert_path) {
        Ok(d) => d,
        Err(e) => {
            log(Level::Error, &format!("Cannot read certificate: {}", e));
            std::process::exit(1);
        }
    };
    let is_pem = install::is_pem_cert(&data);
    log(Level::Info, &format!(
        "Format: {}",
        if is_pem {
            "PEM".bold()
        } else {
            "DER / binary".bold()
        }
    ));

    if !is_pem && !args.force {
        log(Level::Warn, "The file does not look like a PEM certificate (missing -----BEGIN CERTIFICATE-----).");
        log(Level::Info, "Re-run with --force to import it anyway.");
        std::process::exit(1);
    }

    // ───── 4. Check if already trusted ─────
    let pb = spinner("Checking if certificate is already trusted…");
    let already_trusted = is_cert_already_trusted(&cert_path, &os)?;
    pb.finish_and_clear();

    if already_trusted {
        log(Level::Info, "Certificate is already registered in the system trust store.");
        if args.yes {
            log(Level::Info, "Nothing to do. Exiting.");
            return Ok(());
        }
        if !confirm("Re-import anyway?")? {
            log(Level::Info, "Skipped by user.");
            return Ok(());
        }
    }

    // ───── 5. Privilege check ─────
    let pb = spinner("Checking privileges…");
    let elevated = has_elevated_privileges();
    pb.finish_and_clear();

    if elevated {
        log(Level::Success, "Running with elevated privileges (administrator / root).");
    } else {
        log(Level::Warn, "Not running with elevated privileges — the import will likely fail.");
        match os {
            OsFamily::Windows => log(Level::Info, "Right-click the terminal → Run as Administrator."),
            _ => log(Level::Info, "Re-run this tool with sudo."),
        }
        if !args.yes && !confirm("Continue anyway?")? {
            log(Level::Info, "Aborted by user.");
            return Ok(());
        }
    }

    // ───── 6. Confirmation ─────
    if !args.yes {
        if !confirm(&format!(
            "Import {} into the system trust store?",
            cert_path.display()
        ))? {
            log(Level::Info, "Aborted by user.");
            return Ok(());
        }
    }

    // ───── 7. Import ─────
    let pb = spinner("Importing certificate into the trust store…");
    match install_certificate(&cert_path, &os, args.force) {
        Ok(()) => {
            pb.finish_and_clear();
            log(Level::Success, "Certificate imported into the system trust store.");
        }
        Err(e) => {
            pb.finish_and_clear();
            log(Level::Error, &format!("Import failed: {}", e));
            match os {
                OsFamily::Windows => log(
                    Level::Info,
                    "Retry as Administrator: right-click the terminal → Run as Administrator.",
                ),
                OsFamily::MacOS => log(
                    Level::Info,
                    "Retry with elevated privileges: sudo ./certy",
                ),
                OsFamily::Linux => log(
                    Level::Info,
                    "Retry with root: sudo ./certy",
                ),
            }
            std::process::exit(1);
        }
    }

    // ───── 8. Verify ─────
    let pb = spinner("Verifying installation…");
    match verify_install(&cert_path, &os) {
        Ok(true) => {
            pb.finish_and_clear();
            log(Level::Success, "Verification passed: certificate is registered in the trust store.");
        }
        Ok(false) => {
            pb.finish_and_clear();
            log(Level::Warn, "Verification could not confirm the entry (this is often harmless).");
        }
        Err(e) => {
            pb.finish_and_clear();
            log(Level::Warn, &format!("Verification skipped: {}", e));
        }
    }

    println!();
    log(Level::Info, "Notes:");
    log(Level::Info, "  • Chrome and Firefox maintain their own certificate stores and will not pick up this change.");
    log(Level::Info, "  • Restart affected applications (or reboot on Windows) for the change to take full effect.");
    log(Level::Info, "  • Remove the certificate later via the OS certificate manager or trust-store command.");
    println!();
    log(Level::Success, "Done.");

    Ok(())
}
