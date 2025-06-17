use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::fs;
use std::panic;
use std::path::Path;
use std::thread;
use io::ErrorKind;
use syslog::{BasicLogger, Facility, Formatter3164};
use toml;
use yubihsm::audit::commands::LogEntry;
use yubihsm::{Client, Connector, Credentials, HttpConfig};

// Define your configuration struct
#[derive(Deserialize)]
struct DeviceConfig {
    ip_addr: String,
    port: u16,
    audit_key_id: u16,
    password: String,
}

fn main() {
    let configs = load_config();
    if let Err(e) = configs {
        eprintln!("Failed to load device configurations: {}", e);
        return;
    }
    let configs = configs.unwrap();

    setup_logging().unwrap_or_else(|err| {
        panic!("error setting up logging: {}", err);
    });

    let mut handles = Vec::new();

    for device in configs {
        let http_config = HttpConfig {
            addr: device.ip_addr,
            port: device.port,
            timeout_ms: 15000,
        };
        let credentials =
            Credentials::from_password(device.audit_key_id, device.password.as_bytes());
        handles.push(std::thread::spawn(move || {
            device_thread(&http_config, &credentials)
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

fn load_config() -> std::io::Result<Vec<DeviceConfig>> {
    let mut configs = Vec::new();

    for entry in fs::read_dir("./config")? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.chars().all(|c| c.is_ascii_digit()) {
                    let contents = fs::read_to_string(&path)?;
                    match toml::from_str::<DeviceConfig>(&contents) {
                        Ok(config) => configs.push(config),
                        Err(e) => eprintln!("Failed to parse {:?}: {}", path, e),
                    }
                }
            }
        }
    }

    Ok(configs)
}

fn device_thread(http_config: &HttpConfig, credentials: &Credentials) {
    // Connect to the HSM and authenticate with the given credentials
    let mut hsm_client = Client::create(Connector::http(http_config), credentials.clone()).unwrap();

    loop {
        // Re-fetch device info to ensure we have the latest state
        let device_info = match hsm_client.device_info() {
            Ok(info) => info,
            Err(err) => {
                println!("Failed to get device info: {}", err);
                // Attempt to reconnect and fetch device info again
                hsm_client =
                    Client::create(Connector::http(http_config), credentials.clone()).unwrap();
                match hsm_client.device_info() {
                    Ok(info) => info,
                    Err(e) => panic!("Failed to get device info after reconnect: {}", e),
                }
            }
        };

        println!("Logs used: {}", device_info.log_store_used);
        if device_info.log_store_used > 1 {
            hsm_client
                .connect()
                .unwrap_or_else(|err| panic!("error connecting to HSM: {}", err));
            let logs = hsm_client
                .get_log_entries()
                .unwrap_or_else(|err| panic!("error getting log entries: {}", err));
            let serial_number = device_info.serial_number.to_string();
            let version_str = format!(
                "{}.{}.{}",
                device_info.major_version, device_info.minor_version, device_info.build_version
            );

            let mut entry_num = 0;
            for entry in logs.entries.iter() {
                let local_entry = build_log_entry(entry, &serial_number, &version_str);
                let serialized = serde_json::to_string(&local_entry).unwrap();
                log::info!("{}", &serialized);
                //println!("Log sent to syslog: {}", serialized);
                entry_num = local_entry.item;
            }
            hsm_client
                .set_log_index(entry_num)
                .unwrap_or_else(|err| panic!("error setting log index: {}", err));
        }
        thread::sleep(std::time::Duration::from_secs(15));
    }
}

fn setup_logging() -> Result<(), Box<dyn std::error::Error>> {
    let formatter = Formatter3164 {
        facility: Facility::LOG_DAEMON,
        hostname: None,
        process: Path::new(&std::env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
        pid: std::process::id() as i32,
    };

    let logger = syslog::unix(formatter)?;
    let basic_logger = BasicLogger::new(logger);
    log::set_boxed_logger(Box::new(basic_logger))?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}

fn build_log_entry(entry: &LogEntry, serial: &str, version_str: &str) -> LocalLogEntry {
    LocalLogEntry {
        serial: serial.to_string(),
        version: version_str.to_string(),
        item: entry.item,
        cmd: format!("{:?}", entry.cmd),
        length: entry.length,
        session_key: entry.session_key,
        target_key: entry.target_key,
        second_key: entry.second_key,
        result: format!("{:?}", entry.result),
        tick: entry.tick,
        digest: entry
            .digest
            .0
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect(),
        data: format!(
            "{:04x}{:02x}{:04x}{:04x}{:04x}{:04x}{:02x}{:08x}",
            entry.item,
            entry.cmd.to_u8(),
            entry.length,
            entry.session_key,
            entry.target_key,
            entry.second_key,
            entry.result.to_u8(),
            entry.tick
        ),
    }
}

/// Entry in the log response
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct LocalLogEntry {
    /// Serial number string
    pub serial: String,

    /// Version string
    pub version: String,

    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: String,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: u16,

    /// Target key ID
    pub target_key: u16,

    /// Second key affected
    pub second_key: u16,

    /// Result of the operation
    pub result: String,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: String,

    /// Generic log entry composed of the above fields
    pub data: String,
}
