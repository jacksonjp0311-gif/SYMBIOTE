//! OS-provided resource counters for an owned child only. These are separate
//! from logical experiment costs. No process lookup or executable is accepted.
//! Native layouts/units: Microsoft PROCESS_MEMORY_COUNTERS and GetProcessTimes:
//! https://learn.microsoft.com/windows/win32/api/psapi/ns-psapi-process_memory_counters
//! https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
//! Linux VmHWM/VmRSS accounting caveat:
//! https://man7.org/linux/man-pages/man5/proc_pid_status.5.html
use serde::Serialize;
use serde_json::{json, Value};
use std::process::Child;

#[derive(Clone, Serialize)]
pub(super) struct Snapshot {
    pub(super) pid: u32,
    peak_resident_bytes: Option<u64>,
    resident_bytes_at_capture: Option<u64>,
    memory_source: &'static str,
    memory_precision: &'static str,
    memory_capture: Option<&'static str>,
    memory_error: Option<&'static str>,
    cpu_user_100ns: Option<u64>,
    cpu_kernel_100ns: Option<u64>,
    cpu_source: &'static str,
    cpu_capture: Option<&'static str>,
    cpu_error: Option<&'static str>,
}
impl Snapshot {
    fn unavailable(pid: u32, memory_error: &'static str, cpu_error: &'static str) -> Self {
        Self {
            pid,
            peak_resident_bytes: None,
            resident_bytes_at_capture: None,
            memory_source: "unavailable",
            memory_precision: "unavailable",
            memory_capture: None,
            memory_error: Some(memory_error),
            cpu_user_100ns: None,
            cpu_kernel_100ns: None,
            cpu_source: "unavailable",
            cpu_capture: None,
            cpu_error: Some(cpu_error),
        }
    }
    pub(super) fn merge(&mut self, mut latest: Self, stage: &'static str) {
        if latest.peak_resident_bytes.is_some() {
            self.peak_resident_bytes = latest.peak_resident_bytes;
            self.resident_bytes_at_capture = latest.resident_bytes_at_capture;
            self.memory_source = latest.memory_source;
            self.memory_precision = latest.memory_precision;
            self.memory_capture = Some(stage);
        }
        self.memory_error = latest.memory_error.take();
        if latest.cpu_user_100ns.is_some() && latest.cpu_kernel_100ns.is_some() {
            self.cpu_user_100ns = latest.cpu_user_100ns;
            self.cpu_kernel_100ns = latest.cpu_kernel_100ns;
            self.cpu_source = latest.cpu_source;
            self.cpu_capture = Some(stage);
        }
        self.cpu_error = latest.cpu_error.take();
    }
    pub(super) fn json(&self, reaped: bool) -> Value {
        let mut value =
            serde_json::to_value(self).expect("native bounded resource snapshot serializes");
        value["schema"] = json!("symbiote.owned-process-resources/1");
        value["platform"] = json!(std::env::consts::OS);
        value["memory_available"] = json!(self.peak_resident_bytes.is_some());
        value["cpu_available"] =
            json!(self.cpu_user_100ns.is_some() && self.cpu_kernel_100ns.is_some());
        value["peak_is_os_reported"] = json!(self.peak_resident_bytes.is_some());
        value["sampled_peak"] = json!(false);
        value["process_reaped"] = json!(reaped);
        value["scope"] = json!("this owned process only; excludes other processes and descendants");
        value["lifetime_peak_complete"] =
            json!(self.memory_capture == Some("after-exit-owned-handle"));
        value
    }
}

pub(super) fn owned(child: &Child, stage: &'static str) -> Snapshot {
    let mut snapshot = native(child);
    if snapshot.peak_resident_bytes.is_some() {
        snapshot.memory_capture = Some(stage);
    }
    if snapshot.cpu_user_100ns.is_some() {
        snapshot.cpu_capture = Some(stage);
    }
    snapshot
}
pub(super) fn after_reap_supported() -> bool {
    cfg!(windows)
}
pub(super) fn current(stage: &'static str) -> Value {
    let mut snapshot = native_current();
    if snapshot.peak_resident_bytes.is_some() {
        snapshot.memory_capture = Some(stage);
    }
    if snapshot.cpu_user_100ns.is_some() {
        snapshot.cpu_capture = Some(stage);
    }
    let mut value = snapshot.json(false);
    value["scope"] =
        json!("controller process only; excludes child processes and total system memory");
    value
}

#[cfg(windows)]
fn native(child: &Child) -> Snapshot {
    use std::os::windows::io::AsRawHandle;
    windows_snapshot(child.id(), child.as_raw_handle())
}
#[cfg(windows)]
fn native_current() -> Snapshot {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }
    // SAFETY: The pseudo-handle identifies only this calling process, remains
    // valid for its lifetime, and is never closed by this module.
    windows_snapshot(std::process::id(), unsafe { GetCurrentProcess() })
}
#[cfg(windows)]
fn windows_snapshot(pid: u32, handle: *mut std::ffi::c_void) -> Snapshot {
    use std::ffi::c_void;
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    impl FileTime {
        fn ticks(&self) -> u64 {
            (u64::from(self.high) << 32) | u64::from(self.low)
        }
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
        fn GetProcessTimes(
            process: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let mut result = Snapshot::unavailable(
        pid,
        "owned process memory query unavailable",
        "owned process CPU query unavailable",
    );
    let size = std::mem::size_of::<ProcessMemoryCounters>() as u32;
    let mut counters = ProcessMemoryCounters {
        cb: size,
        ..ProcessMemoryCounters::default()
    };
    // SAFETY: This borrowed OS handle belongs to Child, is not closed here, and
    // the repr(C) buffer/size match Microsoft's PROCESS_MEMORY_COUNTERS layout.
    if unsafe { K32GetProcessMemoryInfo(handle, &mut counters, size) } != 0 {
        result.peak_resident_bytes = Some(counters.peak_working_set_size as u64);
        result.resident_bytes_at_capture = Some(counters.working_set_size as u64);
        result.memory_source =
            "K32GetProcessMemoryInfo.PROCESS_MEMORY_COUNTERS.PeakWorkingSetSize/WorkingSetSize";
        result.memory_precision =
            "OS working-set accounting in bytes; not private allocations or total system memory";
        result.memory_error = None;
    }
    let (mut creation, mut exit, mut kernel, mut user) = (
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
        FileTime::default(),
    );
    // SAFETY: All outputs point to initialized FILETIME-compatible buffers and
    // the queried process remains bound to the owned Child handle after exit.
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } != 0 {
        result.cpu_user_100ns = Some(user.ticks());
        result.cpu_kernel_100ns = Some(kernel.ticks());
        result.cpu_source = "GetProcessTimes; summed thread CPU time in raw 100-nanosecond units";
        result.cpu_error = None;
    }
    result
}

#[cfg(target_os = "linux")]
fn native(child: &Child) -> Snapshot {
    linux_snapshot(child.id())
}
#[cfg(target_os = "linux")]
fn native_current() -> Snapshot {
    linux_snapshot(std::process::id())
}
#[cfg(target_os = "linux")]
fn linux_snapshot(pid: u32) -> Snapshot {
    use std::io::Read;
    let mut result = Snapshot::unavailable(
        pid,
        "owned /proc memory counters unavailable",
        "CPU ticks not measured by this backend",
    );
    let Ok(file) = std::fs::File::open(format!("/proc/{pid}/status")) else {
        return result;
    };
    let mut bytes = Vec::new();
    if file.take(65_537).read_to_end(&mut bytes).is_err() || bytes.len() > 65_536 {
        return result;
    }
    if let Ok((peak, current)) = parse_linux_status(&String::from_utf8_lossy(&bytes), pid) {
        result.peak_resident_bytes = Some(peak);
        result.resident_bytes_at_capture = Some(current);
        result.memory_source = "/proc/owned-PID/status.VmHWM/VmRSS";
        result.memory_precision="kernel-reported approximate resident accounting; Linux documents VmHWM/VmRSS as inaccurate";
        result.memory_error = None;
    }
    result
}
#[cfg(not(any(windows, target_os = "linux")))]
fn native(child: &Child) -> Snapshot {
    Snapshot::unavailable(
        child.id(),
        "no verified native peak-memory backend on this platform",
        "no verified native CPU-time backend on this platform",
    )
}
#[cfg(not(any(windows, target_os = "linux")))]
fn native_current() -> Snapshot {
    Snapshot::unavailable(
        std::process::id(),
        "no verified native peak-memory backend on this platform",
        "no verified native CPU-time backend on this platform",
    )
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_status(status: &str, pid: u32) -> Result<(u64, u64), ()> {
    let (mut actual_pid, mut peak, mut current) = (None, None, None);
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            if actual_pid
                .replace(value.trim().parse::<u32>().map_err(|_| ())?)
                .is_some()
            {
                return Err(());
            }
        }
        for (prefix, target) in [("VmHWM:", &mut peak), ("VmRSS:", &mut current)] {
            if let Some(value) = line.strip_prefix(prefix) {
                let mut parts = value.split_whitespace();
                let number = parts.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
                if parts.next() != Some("kB")
                    || parts.next().is_some()
                    || target
                        .replace(number.checked_mul(1024).ok_or(())?)
                        .is_some()
                {
                    return Err(());
                }
            }
        }
    }
    if actual_pid != Some(pid) {
        return Err(());
    }
    Ok((peak.ok_or(())?, current.ok_or(())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_status_requires_owned_pid_units_complete_fields_and_no_overflow() {
        assert_eq!(
            parse_linux_status("Pid:\t42\nVmHWM:\t2048 kB\nVmRSS:\t1024 kB\n", 42),
            Ok((2_097_152, 1_048_576))
        );
        for invalid in [
            "Pid: 41\nVmHWM: 2 kB\nVmRSS: 1 kB\n",
            "Pid: 42\nVmHWM: 2 MB\nVmRSS: 1 kB\n",
            "Pid: 42\nVmHWM: 18446744073709551615 kB\nVmRSS: 1 kB\n",
            "Pid: 42\nVmHWM: 2 kB\n",
            "Pid: 42\nPid: 42\nVmHWM: 2 kB\nVmRSS: 1 kB\n",
        ] {
            assert!(parse_linux_status(invalid, 42).is_err());
        }
    }
    #[test]
    fn unsupported_measurement_is_explicit_null_and_not_a_zero_peak() {
        let snapshot = Snapshot::unavailable(42, "unsupported", "unsupported").json(false);
        assert!(snapshot["peak_resident_bytes"].is_null());
        assert!(snapshot["resident_bytes_at_capture"].is_null());
        assert_eq!(snapshot["memory_available"], false);
        assert_eq!(snapshot["peak_is_os_reported"], false);
        assert_eq!(snapshot["sampled_peak"], false);
    }
}
