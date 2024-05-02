// Creates the basic node structure to be implemented by identity nodes

// Convert to protocol buffers syntax proto2
pub struct Node {
    name: Option<String>,
    description: Option<String>,
    // The protocol version identifies the family of protocols used by the peer. Optional, but recommended.
    protocol_version: Option<String>,
    // Ex v1.0.0, the current identities declared node version
    agent_version: Option<String>,
    public_key: Option<Vec<u8>>,
}

// TODO:: Implement basic node instantiation with name, protocol version and public key(For now can be a string)
// TODO:: Implement key import through file

fn main() {
    println!("Hello, world!");
}
