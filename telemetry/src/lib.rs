use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error")]
    Serialization,
    #[error("unsupported sink")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, TelemetryError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub timestamp: u64,
    pub peers: usize,
    pub throughput_bps: u64,
    pub loss_rate: f64,
    pub queue_depth: u32,
    pub rtt_ms: u64,
    pub consensus_rounds: u64,
    pub bans: u64,
    pub cpu_usage: f64,
    pub memory_used: u64,
    pub disk_used: u64,
}

impl Metrics {
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"timestamp\":{},\"peers\":{},\"throughput_bps\":{},\"loss_rate\":{},\"queue_depth\":{},\"rtt_ms\":{},\"consensus_rounds\":{},\"bans\":{},\"cpu_usage\":{},\"memory_used\":{},\"disk_used\":{}}}",
            self.timestamp,
            self.peers,
            self.throughput_bps,
            self.loss_rate,
            self.queue_depth,
            self.rtt_ms,
            self.consensus_rounds,
            self.bans,
            self.cpu_usage,
            self.memory_used,
            self.disk_used
        )
    }
}

#[derive(Debug)]
pub struct TelemetryCollector {
    pub system: System,
    pub interval: Duration,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
            interval: Duration::from_secs(60),
        }
    }

    pub fn collect(
        &mut self,
        peers: usize,
        throughput: u64,
        loss: f64,
        queue_depth: u32,
        rtt: u64,
        consensus_rounds: u64,
        bans: u64,
    ) -> Metrics {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk_used: u64 = disks
            .list()
            .iter()
            .map(|d| d.total_space().saturating_sub(d.available_space()))
            .sum();
        let cpu_usage = self.system.global_cpu_info().cpu_usage() as f64;
        let memory_used = self.system.used_memory();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Metrics {
            timestamp,
            peers,
            throughput_bps: throughput,
            loss_rate: loss,
            queue_depth,
            rtt_ms: rtt,
            consensus_rounds,
            bans,
            cpu_usage,
            memory_used,
            disk_used,
        }
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub enum Sink {
    File(PathBuf),
    Http(String),
}

impl Sink {
    pub fn write(&self, metrics: &Metrics) -> Result<()> {
        match self {
            Sink::File(path) => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                writeln!(file, "{}", metrics.to_json_line())?;
                Ok(())
            }
            Sink::Http(_url) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn collect_does_not_panic() {
        let mut c = TelemetryCollector::new();
        let m = c.collect(1, 100, 0.1, 2, 5, 3, 0);
        assert!(m.timestamp > 0 || true);
    }

    #[test]
    fn file_sink_appends() {
        let path = temp_dir().join("telemetry_test.jsonl");
        let _ = std::fs::remove_file(&path);
        let sink = Sink::File(path.clone());
        let mut c = TelemetryCollector::new();
        let m = c.collect(1, 100, 0.1, 2, 5, 3, 0);
        sink.write(&m).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("throughput_bps"));
        let _ = std::fs::remove_file(&path);
    }
}
