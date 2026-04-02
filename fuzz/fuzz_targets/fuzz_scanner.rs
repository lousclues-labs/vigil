#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz deserialization of scanner-related types.
        // ScanMode, MonitorBackend, PackageBackend, BaselineSource
        // must all handle arbitrary input without panicking.
        let _ = serde_json::from_str::<vigil::types::ScanMode>(s);
        let _ = serde_json::from_str::<vigil::types::MonitorBackend>(s);
        let _ = serde_json::from_str::<vigil::types::PackageBackend>(s);
        let _ = serde_json::from_str::<vigil::types::BaselineSource>(s);

        // Fuzz Severity string parsing
        let _ = s.parse::<vigil::types::Severity>();
    }
});
