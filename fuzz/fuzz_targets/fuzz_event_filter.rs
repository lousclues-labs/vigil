#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use vigil::config::Config;
use vigil::filter::EventFilter;
use vigil::types::{FsEvent, FsEventType};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    path: String,
    event_type: u8,
}

fuzz_target!(|input: FuzzInput| {
    let toml_str = r#"
        [watch.test]
        severity = "medium"
        paths = ["/tmp/test"]
    "#;
    let config: Config = match toml::from_str(toml_str) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut filter = EventFilter::new(&config);

    let event_type = match input.event_type % 6 {
        0 => FsEventType::Modify,
        1 => FsEventType::Attrib,
        2 => FsEventType::Create,
        3 => FsEventType::Delete,
        4 => FsEventType::MovedFrom,
        _ => FsEventType::MovedTo,
    };

    let event = FsEvent {
        path: std::sync::Arc::new(std::path::PathBuf::from(&input.path)),
        event_type,
        timestamp: chrono::Utc::now(),
        event_fd: None,
        process: None,
        bloom_generation: 0,
    };

    let _ = filter.should_process(&event);
});
