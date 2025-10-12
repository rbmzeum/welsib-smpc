use crate::server::WelsibContext;
use crate::server::context::WelsibState;
use crate::smpc::response::handshake::HandshakeResponseAttributes;
use crate::smpc::response::SMPCResponse;
// use crate::smpc::WelsibDtoInterface;

impl WelsibContext {
    pub fn do_handshake(&mut self) {
        // println!("DEBUG DO Handshake");
        let private_key = self.keypair.get_secret_key();
        let smpc_handshake_response_attributes = HandshakeResponseAttributes::new(&private_key);
        let smpc_handshake_response_command = Some(SMPCResponse::make(smpc_handshake_response_attributes.to_json(), &private_key));
        if let Some(smpc_handshake_response_command) = smpc_handshake_response_command {
            self.set_smpc_response(smpc_handshake_response_command);
        }
        self.set_state(WelsibState::AwaitOutput);
    }
}