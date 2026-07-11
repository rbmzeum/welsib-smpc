#[derive(Debug, Copy, Clone, PartialEq)]
pub enum WelsibState {
    AwaitBegin,
    AwaitRouter,
    AwaitHandshake,
    AwaitSendBitProof,
    AwaitSendSlot,
    AwaitSendPointMatrix,
    AwaitSendPointList,
    AwaitSendPointRangeVerificationKey,
    AwaitReceiveSlot,
    AwaitReset,
    AwaitOutput,
    Done,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RequestType {
    // ...
}
