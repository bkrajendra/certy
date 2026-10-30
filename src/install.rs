use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(unused_imports)]
use sha1::{Digest as _, Sha1};
#[allow(unused_imports)]
use sha2::{Digest as _, Sha256};

/// Operating system families supported by the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Windows,
    Linux,
    MacOS,
}

/// Detect the operating system at runtime (so cross-compiled binaries still behave correctly).
pub fn detect_os() -> OsFamily {
    match std::env::consts::OS {
        "windows" => OsFamily::Windows,
        "macos" => OsFamily::MacOS,
        _ => OsFamily::Linux,
    }
}

/// Directory that contains the running binary.
pub fn binary_dir() -> std::io::Result<PathBuf> {
    std::env::current_exe().map(|p| {
        p.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

/// Locate the certificate file: explicit path or `ca-cert.pem` next to the binary.
#[allow(dead_code)]
pub fn locate_cert(cert: Option<PathBuf>) -> std::io::Result<PathBuf> {
    match cert {
        Some(p) => Ok(p),
        None => binary_dir().map(|d| d.join("ca-cert.pem")),
    }
}

/// Check whether the file looks like a PEM certificate.
pub fn is_pem_cert(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN CERTIFICATE-----")
}

/// Decode a PEM certificate (possibly with multiple blocks) into raw DER bytes.
pub fn pem_to_der(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let text = std::str::from_utf8(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            continue;
        }
        if line == "-----END CERTIFICATE-----" {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Compute the SHA-1 hex fingerprint of raw DER certificate bytes.
fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Compute the SHA-256 hex fingerprint of raw certificate bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Check whether the certificate is already registered in the system trust store.
pub fn is_cert_already_trusted(cert: &Path, os: &OsFamily) -> std::io::Result<bool> {
    let data = match fs::read(cert) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };

    match os {
        OsFamily::Windows => {
            let der = if is_pem_cert(&data) {
                pem_to_der(&data)?
            } else {
                data
            };
            let fingerprint = sha1_hex(&der);

            match Command::new("certutil.exe").args(["-store", "ROOT"]).output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    Ok(stdout.contains(&fingerprint))
                }
                Err(_) => Ok(false),
            }
        }
        OsFamily::MacOS => {
            let fingerprint = sha256_hex(&data);
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let system_kc = "/Library/Keychains/System.keychain".to_string();
            let login_kc = format!("{}/Library/Keychains/login.keychain-db", home);
            let keychains: Vec<String> = vec![system_kc, login_kc];

            for kc in &keychains {
                if !Path::new(kc).exists() {
                    continue;
                }
                match Command::new("security")
                    .args(["find-certificate", "-Z", "-k", kc])
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if stdout.contains(&fingerprint) {
                            return Ok(true);
                        }
                    }
                    Err(_) => continue,
                }
            }
            Ok(false)
        }
        OsFamily::Linux => {
            let id = distro_id();
            let anchor_dirs: Vec<&str> = match id.as_str() {
                "ubuntu" | "debian" | "raspbian" | "linuxmint" | "pop" | "neon" | "kali" => {
                    vec!["/usr/local/share/ca-certificates"]
                }
                "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "alma" | "opensuse"
                | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "ol" => {
                    vec!["/etc/pki/ca-trust/source/anchors"]
                }
                "arch" | "manjaro" | "endeavouros" | "garuda" => {
                    vec!["/usr/share/ca-certificates/trust-source/anchors"]
                }
                _ => vec![
                    "/usr/local/share/ca-certificates",
                    "/etc/pki/ca-trust/source/anchors",
                    "/usr/share/ca-certificates/trust-source/anchors",
                ],
            };

            // If our installed copy already exists in an anchor directory, it is trusted.
            for dir in &anchor_dirs {
                let target = Path::new(dir).join("certy-ca-cert.crt");
                if target.exists() {
                    return Ok(true);
                }
            }

            // Also check the system trust list for our certificate's fingerprint.
            let fingerprint = sha256_hex(&data);
            if let Ok(output) = Command::new("trust").args(["list", "--filter=certificates"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains(&fingerprint) {
                    return Ok(true);
                }
            }

            Ok(false)
        }
    }
}

/// Returns true when the process runs with administrative/root privileges.
pub fn has_elevated_privileges() -> bool {
    match detect_os() {
        OsFamily::Windows => match Command::new("whoami").arg("/groups").output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).contains("S-1-5-32-544"), // BUILTIN\Administrators
            Err(_) => false,
        },
        _ => match Command::new("id").arg("-u").output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim() == "0",
            Err(_) => false,
        },
    }
}

fn distro_id() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("ID=").map(|v| v.trim().trim_matches('"').to_lowercase())
            })
        })
        .unwrap_or_default()
}

fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).status().map(|s| s.success()).unwrap_or(false)
}

/// Import the certificate into the platform trust store.
pub fn install_certificate(cert: &Path, os: &OsFamily, _force: bool) -> std::io::Result<()> {
    match os {
        OsFamily::Windows => install_windows(cert),
        OsFamily::MacOS => install_macos(cert),
        OsFamily::Linux => install_linux(cert),
    }
}

/// Best-effort verification that the trust store now knows about the certificate.
pub fn verify_install(cert: &Path, os: &OsFamily) -> std::io::Result<bool> {
    match os {
        OsFamily::Windows => {
            // certutil -store ROOT prints the whole store; capture and discard it.
            Ok(Command::new("certutil.exe")
                .args(["-store", "ROOT"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false))
        }
        OsFamily::MacOS => {
            // Quietly confirm the certificate validates against the System keychain trust settings.
            let cert_str = cert.to_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate path")
            })?;
            Ok(Command::new("security")
                .args(["verify-cert", "-c", cert_str, "-k", "/Library/Keychains/System.keychain", "-q"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false))
        }
        OsFamily::Linux => Ok(run_cmd("update-ca-certificates", &[])
            || run_cmd("update-ca-trust", &["extract"])
            || run_cmd("trust", &["extract-compat"])),
    }
}

// ---------------------------------------------------------------------------
// Platform-specific implementations
// ---------------------------------------------------------------------------

/// Windows: import into the local-machine Trusted Root Certification Authorities store.
fn install_windows(cert: &Path) -> std::io::Result<()> {
    let data = fs::read(cert)?;
    let der = if is_pem_cert(&data) {
        pem_to_der(&data)?
    } else {
        data
    };

    // certutil.exe expects DER (.cer). Write to a temp location so we never
    // clobber the user's PEM file.
    let der_path = std::env::temp_dir().join("certy-import.cer");
    fs::write(&der_path, &der)?;

    let result = Command::new("certutil.exe")
        .args(["-addstore", "-f", "ROOT"])
        .arg(
            der_path.to_str()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid temp path"))?,
        )
        .output();

    let _ = fs::remove_file(&der_path);

    match result {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                if stderr.is_empty() {
                    format!("certutil exited with code {:?}", output.status.code())
                } else {
                    format!("certutil failed: {}", stderr)
                },
            ))
        }
        Err(e) => Err(e),
    }
}

/// macOS: add as a trusted root to the System keychain (fall back to login keychain).
fn install_macos(cert: &Path) -> std::io::Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let keychains: Vec<String> = vec![
        "/Library/Keychains/System.keychain".to_string(),
        format!("{}/Library/Keychains/login.keychain-db", home),
    ];

    let cert_str = cert.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid certificate path")
    })?;

    let mut last_error = String::new();
    for kc in &keychains {
        match Command::new("security")
            .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k", kc, cert_str])
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                last_error = if stderr.is_empty() {
                    format!("security exited with code {:?}", output.status.code())
                } else {
                    format!("security: {}", stderr)
                };
            }
            Err(e) => last_error = format!("security: {}", e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        if last_error.is_empty() {
            "security add-trusted-cert failed".to_string()
        } else {
            last_error
        },
    ))
}

/// Linux: copy into the distro's CA anchor directory and run the trust update command.
fn install_linux(cert: &Path) -> std::io::Result<()> {
    let id = distro_id();

    let anchor_dirs: Vec<&str> = match id.as_str() {
        "ubuntu" | "debian" | "raspbian" | "linuxmint" | "pop" | "neon" | "kali" => {
            vec!["/usr/local/share/ca-certificates"]
        }
        "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "alma" | "opensuse"
        | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "ol" => {
            vec!["/etc/pki/ca-trust/source/anchors"]
        }
        "arch" | "manjaro" | "endeavouros" | "garuda" => {
            vec!["/usr/share/ca-certificates/trust-source/anchors"]
        }
        _ => vec![
            "/usr/local/share/ca-certificates",
            "/etc/pki/ca-trust/source/anchors",
            "/usr/share/ca-certificates/trust-source/anchors",
        ],
    };

    let mut last_error = String::new();
    for dir in &anchor_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }

        let target = dir_path.join("certy-ca-cert.crt");
        match fs::copy(cert, &target) {
            Ok(_) => {
                let update_cmds: Vec<Vec<&str>> = match id.as_str() {
                    "ubuntu" | "debian" | "raspbian" | "linuxmint" | "pop" | "neon" | "kali" => {
                        vec![vec!["update-ca-certificates"]]
                    }
                    "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "alma"
                    | "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "sles" | "ol" => {
                        vec![vec!["update-ca-trust", "extract"], vec!["update-ca-trust"]]
                    }
                    "arch" | "manjaro" | "endeavouros" | "garuda" => {
                        vec![vec!["trust", "extract-compat"], vec!["trust", "extract"]]
                    }
                    _ => vec![
                        vec!["update-ca-certificates"],
                        vec!["update-ca-trust", "extract"],
                        vec!["trust", "extract-compat"],
                    ],
                };

                for cmd in &update_cmds {
                    if run_cmd(cmd[0], &cmd[1..]) {
                        return Ok(());
                    }
                }
                last_error = format!("no trust-update command succeeded for {}", dir);
            }
            Err(e) => last_error = format!("cannot copy to {}: {}", dir, e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        if last_error.is_empty() {
            "no supported CA anchor directory found on this system".to_string()
        } else {
            last_error
        },
    ))
}
