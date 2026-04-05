#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Parse arbitrary bytes as TOML config, then validate.
        // Must never panic.
        if let Ok(config) = toml::from_str::<vigil::config::Config>(s) {
            let _ = vigil::config::validate_config(&config);
        }
    }
});
