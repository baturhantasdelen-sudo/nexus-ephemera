#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = nexus_ephemera::ipc::fuzz_wire_request(data);
    nexus_ephemera::ipc::fuzz_wire_response(data);
});
