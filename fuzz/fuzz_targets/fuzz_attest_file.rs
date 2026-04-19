#![no_main]

use libfuzzer_sys::fuzz_target;
use vigil::attest;

fuzz_target!(|data: &[u8]| {
    // Parser path should never panic on malformed CBOR input.
    if let Ok(att) = attest::format::deserialize_attestation(data) {
        // Round-trip serializer should also be panic-free for parsed values.
        let _ = attest::format::serialize_attestation(&att);
        let _ = attest::format::compute_content_hash(&att.header, &att.body);
    }
});
