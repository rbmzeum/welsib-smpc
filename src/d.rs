pub fn d(s: String) {
    // eprintln!("{s}");
}

const KEYS: [&str; 0] = [
    // "cmp",
    // "cmp_bp",
    // "solution",
    // "range",
    // "key",
    // "send_request",
    // "receive_slot",
    // "agg_received_key",
    // "decode_key",
    // "run_runners",
    // "run",

    // "send_slot_key",
    // "receive_slot_key",

    // "keypair",
    // ""
];

pub fn dd(s: String, key: &str) {
    if KEYS.contains(&key) {
        eprintln!("{s}");
    }
}



/*
welsib_smpc::d::d(format!("DEBUG: {:#?}", value));
*/