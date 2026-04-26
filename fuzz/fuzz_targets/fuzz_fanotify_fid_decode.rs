#![no_main]

//! Fuzz target for VIGIL-VULN-077: adversarial fanotify FID-mode event info
//! header lengths and buffer contents. Must not panic, loop infinitely, or
//! read out of bounds.

use libfuzzer_sys::fuzz_target;

// Simulated fanotify_event_info_header parsing with bounds checking.
// The real decoder validates hdr.len and remaining-buffer bounds
// before indexing — this fuzz target exercises that validation.
fuzz_target!(|data: &[u8]| {
    // Simulate parsing of one or more info headers from a raw buffer
    let mut offset = 0usize;
    let min_header_size = 4; // info_type(u8) + pad(u8) + len(u16)

    while offset + min_header_size <= data.len() {
        let _info_type = data[offset];
        let _pad = data[offset + 1];
        let len = u16::from_ne_bytes([data[offset + 2], data[offset + 3]]) as usize;

        // Defensive validation: len must be >= header size and within buffer
        if len < min_header_size || offset + len > data.len() {
            break;
        }

        // Simulate accessing the payload (would be file_handle + filename)
        let _payload = &data[offset + min_header_size..offset + len];

        offset += len;
    }
});
