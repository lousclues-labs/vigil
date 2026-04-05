#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as xattr JSON.
    // The function uses serde_json internally and must never panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<std::collections::HashMap<String, String>>(s);
    }

    // Also try raw bytes through hex encoding (the xattr path)
    let hex_str = hex::encode(data);
    let json_str = format!(r#"{{"test":"{}"}}"#, hex_str);
    let _ = serde_json::from_str::<std::collections::HashMap<String, String>>(&json_str);
});
