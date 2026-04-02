#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz deserialization of BaselineEntry from JSON.
        // This must never panic.
        let _ = serde_json::from_str::<vigil::types::BaselineEntry>(s);

        // Also fuzz ChangeType deserialization
        let _ = serde_json::from_str::<vigil::types::ChangeType>(s);

        // Fuzz Severity parsing
        let _ = s.parse::<vigil::types::Severity>();
    }
});
