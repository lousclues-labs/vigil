#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse arbitrary strings as vigil TOML config.
        // This must never panic.
        let _ = toml::from_str::<vigil::config::Config>(s);
    }
});
