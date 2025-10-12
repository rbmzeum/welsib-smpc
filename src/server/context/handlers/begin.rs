use crate::server::WelsibContext;
use crate::server::context::WelsibState;

impl WelsibContext {
    pub fn do_begin(&mut self) {
        // println!("\nBegin");
        crate::d(format!("DEBUG begin:\n{:?}", &self.stream().is_some()));
        let next_state = if self.stream().is_some() {
            WelsibState::AwaitRouter
        } else {
            WelsibState::Done
        };

        self.set_state(next_state);
    }
}
