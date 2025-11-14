pub fn d(s: String) {
    // eprintln!("{s}");
}

const keys: [&str; 8] = [
    "key",
    // "send_request",
    "receive_slot",
    "agg_received_key",
    // "decode_key",
    "run_runners",
    "run",

    "send_slot_key",
    "receive_slot_key",

    "keypair",
    // ""
];

pub fn dd(s: String, key: &str) {
    if keys.contains(&key) {
        eprintln!("{s}");
    }
}



/*
welsib_smpc::d::d(format!("DEBUG: {:#?}", value));
*/