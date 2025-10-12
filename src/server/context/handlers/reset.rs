use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::server::{context::calculation::Calculation, Encode, Decode, Aggregate};
use crate::smpc::request::SMPCRequest;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::send_slot::SendSlotResponseAttributes;
use crate::smpc::response::{SMPCResponse, ResponseStatus};
// use crate::smpc::WelsibDtoInterface;
use crate::smpc::request::send_slot::SendSlotRequestAttributes;
use std::time::{SystemTime, UNIX_EPOCH};
// use esig::{sign, verify};
// use esig::hash::hash;
// use esig::Signature;
use crate::base64::safe_decode;
use crate::smpc::slot::{Slot, SlotType};

impl WelsibContext {
    pub fn do_reset(&mut self) {
        // println!("DEBUG DO Reset");
    }
}