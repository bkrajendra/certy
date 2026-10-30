use colored::Colorize;

/// Log levels used by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
    Success,
}

/// Print a formatted log line with a colored tag.
pub fn log(level: Level, msg: &str) {
    let tag = match level {
        Level::Info => "INFO".blue().bold(),
        Level::Warn => "WARN".yellow().bold(),
        Level::Error => "ERROR".red().bold(),
        Level::Success => "OK  ".green().bold(),
    };
    println!("[{}] {}", tag, msg);
}

/// Print the professional intro banner.
pub fn banner() {
    let line = "═".repeat(56).cyan().bold();
    println!("╔{}╗", line);
    println!("║ {:^54} ║", "Custom Root CA Importer".cyan().bold());
    println!("║ {:^54} ║", "System trust store installer".white());
    println!("║ {:^54} ║", "Windows · Linux · macOS".white().dimmed());
    println!("║ {:^54} ║", "Author: Rajendra Khope".white().dimmed());
    println!("╚{}╝", line);
    println!();
}
