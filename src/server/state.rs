#[derive(Debug, Copy, Clone, PartialEq)]
pub enum WelsibState {
    AwaitBegin,
    AwaitRouter,
    AwaitHandshake,
    AwaitSendSlot,
    AwaitSendPointMatrix,
    AwaitSendPointList,
    AwaitReceiveSlot,
    AwaitReset,
    AwaitOutput,
    Done,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RequestType {
    // ...
}
