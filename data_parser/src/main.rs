//! AAM Security Event Data Parser
//!
//! Converts UAV attack datasets into SecurityEvent format for passenger drone
//! security experiments. Adapts generic UAV data to eVTOL/air taxi context.
//!
//! Usage:
//!   cargo run --release -- all -i ../data/raw -o ../data/processed
//!
//! Then use with blast.py:
//!   python blast.py --target postgres --data ../data/processed/aam_security_events.csv

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use csv::{Reader, Writer};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// =============================================================================
// DATA MODELS
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttackType {
    Benign = 0,
    GpsSpoofing = 1,
    DenialOfService = 2,
    ManInTheMiddle = 3,
    ReplayAttack = 4,
    GpsJamming = 5,
    EvilTwin = 6,
    FalseDataInjection = 7,
}

impl AttackType {
    fn from_str(s: &str) -> Self {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "gps spoofing" | "gps_spoofing" | "gpsspoofing" | "spoofing" => AttackType::GpsSpoofing,
            "dos" | "dos attack" | "denial of service" | "ping dos" => AttackType::DenialOfService,
            "mitm" | "man in the middle" => AttackType::ManInTheMiddle,
            "replay" | "replay attack" => AttackType::ReplayAttack,
            "gps jamming" | "jamming" | "gps_jamming" => AttackType::GpsJamming,
            "evil twin" | "evil_twin" => AttackType::EvilTwin,
            "fdi" | "false data injection" => AttackType::FalseDataInjection,
            "normal" | "benign" | "none" | "" => AttackType::Benign,
            _ => AttackType::Benign,
        }
    }

    fn to_evtol_context(&self) -> &'static str {
        match self {
            AttackType::GpsSpoofing => "eVTOL_NAV_COMPROMISED",
            AttackType::DenialOfService => "AIRTAXI_COMM_DISRUPTED",
            AttackType::ManInTheMiddle => "VERTIPORT_CMD_INTERCEPT",
            AttackType::ReplayAttack => "FLIGHT_CMD_REPLAY",
            AttackType::GpsJamming => "GNSS_DEGRADED",
            AttackType::EvilTwin => "ROGUE_VERTIPORT",
            AttackType::FalseDataInjection => "SENSOR_MANIPULATION",
            AttackType::Benign => "NORMAL_OPERATION",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp_ms: i64,
    pub event_type: u8,
    pub confidence: u8,
    pub vehicle_id: String,
    pub data_hash: String,
    pub attack_name: String,
    pub evtol_context: String,
}

// =============================================================================
// PARSERS
// =============================================================================

fn parse_cyberattack_dataset(path: &Path) -> Result<Vec<SecurityEvent>> {
    println!("📂 Parsing UAV Cyberattack Dataset...");

    let file = File::open(path).context("Failed to open cyberattack dataset")?;
    let mut rdr = Reader::from_reader(BufReader::new(file));

    let headers = rdr.headers()?.clone();
    let class_idx = headers.iter().position(|h| h == "class").unwrap_or(37);
    let timestamp_idx = headers.iter().position(|h| h.contains("timestamp")).unwrap_or(0);

    let mut events = Vec::new();
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} [{elapsed_precise}] Processed {msg} events").unwrap());

    for (idx, result) in rdr.records().enumerate() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let class_str = record.get(class_idx).unwrap_or("benign");
        let attack_type = AttackType::from_str(class_str);

        let timestamp: i64 = record.get(timestamp_idx)
            .and_then(|s| s.parse().ok())
            .map(|t: f64| (t * 1000.0) as i64)
            .unwrap_or_else(|| 1700000000000 + idx as i64);

        let vehicle_id = format!("EVTOL-{:04X}", (idx * 7) % 256);
        let raw_data: String = record.iter().take(10).collect();
        let data_hash = compute_hash(&raw_data);

        let confidence = match attack_type {
            AttackType::Benign => 0,
            AttackType::DenialOfService => 85,
            AttackType::ReplayAttack => 80,
            _ => 75,
        };

        events.push(SecurityEvent {
            timestamp_ms: timestamp,
            event_type: attack_type as u8,
            confidence,
            vehicle_id,
            data_hash,
            attack_name: format!("{:?}", attack_type),
            evtol_context: attack_type.to_evtol_context().to_string(),
        });

        if idx % 10000 == 0 {
            pb.set_message(format!("{}", idx));
        }
    }

    pb.finish_with_message(format!("{} ✓", events.len()));
    Ok(events)
}

fn parse_vtol_telemetry(base_path: &Path) -> Result<Vec<SecurityEvent>> {
    println!("📂 Parsing PX4 VTOL Telemetry (eVTOL-like)...");

    let vtol_path = base_path.join("Simulated - OTU Survey/PX4-VTOL-SITL");
    if !vtol_path.exists() {
        println!("⚠️  VTOL path not found at {:?}", vtol_path);
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    let mut event_id: u64 = 0;

    for scenario in &["Normal", "GPS Spoofing", "Ping DoS"] {
        let scenario_path = vtol_path.join(scenario);
        if !scenario_path.exists() {
            continue;
        }

        let attack_type = AttackType::from_str(scenario);
        println!("  📁 {} scenario...", scenario);

        for entry in WalkDir::new(&scenario_path)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.path().file_name().unwrap_or_default().to_string_lossy();
                name.contains("vehicle_gps_position") || name.contains("sensor_combined")
            })
            .take(5) // Limit files per scenario
        {
            let file = match File::open(entry.path()) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut rdr = Reader::from_reader(BufReader::new(file));

            for result in rdr.records().take(5000) {
                let record = match result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let timestamp: i64 = record.get(0)
                    .and_then(|s| s.parse().ok())
                    .map(|t: i64| t / 1000) // microseconds to ms
                    .unwrap_or_else(|| 1700000000000 + event_id as i64);

                let raw_data: String = record.iter().take(5).collect();
                let data_hash = compute_hash(&raw_data);

                events.push(SecurityEvent {
                    timestamp_ms: timestamp,
                    event_type: attack_type as u8,
                    confidence: match attack_type {
                        AttackType::Benign => 0,
                        AttackType::GpsSpoofing => 90,
                        AttackType::DenialOfService => 85,
                        _ => 75,
                    },
                    vehicle_id: format!("VTOL-TAXI-{:02}", event_id % 10),
                    data_hash,
                    attack_name: format!("{:?}", attack_type),
                    evtol_context: attack_type.to_evtol_context().to_string(),
                });

                event_id += 1;
            }
        }
    }

    println!("  ✓ {} VTOL events", events.len());
    Ok(events)
}

fn parse_gps_attacks(base_path: &Path) -> Result<Vec<SecurityEvent>> {
    println!("📂 Parsing Live GPS Spoofing/Jamming data...");

    let live_path = base_path.join("Live GPS Spoofing and Jamming");
    if !live_path.exists() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    let mut event_id: u64 = 0;

    for scenario in &["Benign Flight", "GPS Jamming", "GPS Spoofing"] {
        let scenario_path = live_path.join(scenario);
        if !scenario_path.exists() {
            continue;
        }

        let attack_type = AttackType::from_str(scenario);
        println!("  📁 {} ...", scenario);

        for entry in WalkDir::new(&scenario_path)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "csv"))
            .take(3)
        {
            let file = match File::open(entry.path()) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut rdr = Reader::from_reader(BufReader::new(file));

            for result in rdr.records().take(3000) {
                let record = match result {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let timestamp: i64 = record.get(0)
                    .and_then(|s| s.parse().ok())
                    .map(|t: i64| t / 1000)
                    .unwrap_or_else(|| 1700000000000 + event_id as i64);

                let raw_data: String = record.iter().take(5).collect();
                let data_hash = compute_hash(&raw_data);

                events.push(SecurityEvent {
                    timestamp_ms: timestamp,
                    event_type: attack_type as u8,
                    confidence: match attack_type {
                        AttackType::Benign => 0,
                        AttackType::GpsJamming => 95,
                        AttackType::GpsSpoofing => 90,
                        _ => 75,
                    },
                    vehicle_id: format!("EVTOL-LIVE-{:02}", event_id % 20),
                    data_hash,
                    attack_name: format!("{:?}", attack_type),
                    evtol_context: attack_type.to_evtol_context().to_string(),
                });

                event_id += 1;
            }
        }
    }

    println!("  ✓ {} GPS attack events", events.len());
    Ok(events)
}

// =============================================================================
// UTILITIES
// =============================================================================

fn compute_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(&hasher.finalize()[..16]) // 32 hex chars
}

fn write_blast_csv(events: &[SecurityEvent], output_path: &Path) -> Result<()> {
    println!("💾 Writing {} events to {:?}", events.len(), output_path);

    let file = File::create(output_path)?;
    let mut wtr = Writer::from_writer(BufWriter::new(file));

    wtr.write_record(&["timestamp_ms", "event_type", "confidence", "vehicle_id", "data_hash"])?;

    let pb = ProgressBar::new(events.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{bar:40.cyan/blue} {pos}/{len}").unwrap());

    for event in events {
        wtr.write_record(&[
            event.timestamp_ms.to_string(),
            event.event_type.to_string(),
            event.confidence.to_string(),
            event.vehicle_id.clone(),
            event.data_hash.clone(),
        ])?;
        pb.inc(1);
    }

    wtr.flush()?;
    pb.finish();
    Ok(())
}

fn print_stats(events: &[SecurityEvent]) {
    println!("\n📊 DATASET STATISTICS");
    println!("════════════════════════════════════════");
    println!("Total events: {}\n", events.len());

    let mut counts: HashMap<u8, usize> = HashMap::new();
    for event in events {
        *counts.entry(event.event_type).or_insert(0) += 1;
    }

    let names = [
        (0, "Benign          "), (1, "GPS Spoofing    "), (2, "DoS Attack      "),
        (3, "MITM            "), (4, "Replay Attack   "), (5, "GPS Jamming     "),
        (6, "Evil Twin       "), (7, "False Data Inj  "),
    ];

    println!("Attack Type Distribution:");
    for (id, name) in names {
        if let Some(count) = counts.get(&id) {
            let pct = (*count as f64 / events.len() as f64) * 100.0;
            println!("  {} {:>7} ({:5.1}%)", name, count, pct);
        }
    }
    println!("════════════════════════════════════════\n");
}

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(name = "aam_parser")]
#[command(about = "Parse UAV attack datasets → AAM SecurityEvent format for blast.py")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse all datasets and combine
    All {
        #[arg(short, long, default_value = "../data/raw")]
        input: PathBuf,
        #[arg(short, long, default_value = "../data/processed")]
        output: PathBuf,
    },
    /// Parse only cyberattack dataset
    Cyber {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value = "../data/processed")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("🚀 AAM Security Event Parser");
    println!("   UAV attack data → Passenger drone context\n");

    match cli.command {
        Commands::All { input, output } => {
            fs::create_dir_all(&output)?;
            let mut all_events = Vec::new();

            // 1. Cyberattack dataset
            let cyber_path = input.join("uav_cyberattack/Dataset_T-ITS.csv");
            if cyber_path.exists() {
                all_events.extend(parse_cyberattack_dataset(&cyber_path)?);
            }

            // 2. IEEE UAV Attack - VTOL telemetry
            let uav_path = input.join("uav_attack");
            if uav_path.exists() {
                all_events.extend(parse_vtol_telemetry(&uav_path)?);
                all_events.extend(parse_gps_attacks(&uav_path)?);
            }

            print_stats(&all_events);
            write_blast_csv(&all_events, &output.join("aam_security_events.csv"))?;

            println!("✨ Done! Use with blast.py:");
            println!("   python blast.py --target postgres --data {}/aam_security_events.csv", output.display());
        }

        Commands::Cyber { input, output } => {
            fs::create_dir_all(&output)?;
            let events = parse_cyberattack_dataset(&input)?;
            print_stats(&events);
            write_blast_csv(&events, &output.join("cyberattack_events.csv"))?;
        }
    }

    Ok(())
}
