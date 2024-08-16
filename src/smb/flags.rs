use bitflags::bitflags;

bitflags! {
    /// https://wiki.wireshark.org/SMB2#smb2-header-structure
    ///
    /// R:    Response flag.     ==1 if this is a response,          ==0 for a request
    /// P:    PID valid.         ==1 the PID field is valid,         ==0 PID is not valid
    /// C:    End of Chain       ==1 this is the last PDU in a chain
    /// S:    Signature present. ==1 signature is present,           ==0 signature is not present

    //#[derive(Debug, Clone, Eq, PartialEq)]
    //pub struct Flag: u8 {
    //    const S = 0b01000000;
    //    const C = 0b00010000;
    //    const P = 0b00000100;
    //    const R = 0b00000001;
    //
    //    const _ = !0; // Windows try not to put additional undocumented bits challenge impossible
    //}


    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct Flags: u32 {
        ///  When set, indicates the message is a response rather than a
        /// request. This MUST be set on responses sent from the server to the
        /// client, and MUST NOT be set on requests sent from the client to the
        /// server.
        const FlagsServer2Redir = 0x00000001;

        ///  When set, indicates that this is an ASYNC SMB2 header. Always set
        /// for headers of the form described in this section.
        const FlagsAsyncCommand = 0x00000002;

        ///  When set in an SMB2 request, indicates that this request is a
        /// related operation in a compounded request chain. The use of this
        /// flag in an SMB2 request is as specified in section 3.2.4.1.4.
        ///  When set in an SMB2 compound response, indicates that the
        /// request corresponding to this response was part of a related
        /// operation in a compounded request chain. The use of this flag in an
        /// SMB2 response is as specified in section 3.3.5.2.7.2.
        const FlagsRelatedOps   = 0x00000004;

        ///  When set, indicates that this packet has been signed. The use of
        /// this flag is as specified in section 3.1.5.1.
        const FlagsSigned       = 0x00000008;

        ///  This flag is only valid for the SMB 3.1.1 dialect. It is a mask for the
        /// requested I/O priority of the request, and it MUST be a value in the
        /// range 0 to 7.
        const FlagsPriorityMask = 0x00000070;

        ///  When set, indicates that this command is a Distributed File
        /// System (DFS) operation. The use of this flag is as specified in
        /// section 3.3.5.9.
        const FlagsDfsOps       = 0x10000000;

        ///  This flag is only valid for the SMB 3.x dialect family. When set, it
        /// indicates that this command is a replay operation.
        ///  The client MUST ignore this bit on receipt.
        const FlagsRelayOps     = 0x20000000;
    }
}
