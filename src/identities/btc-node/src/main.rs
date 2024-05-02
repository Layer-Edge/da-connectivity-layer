
// Extend the Node struct to include the Bitcoin node specific fields
pub struct BtcNode {
    node: Node,
    // The Bitcoin node relay
    relay: reqwest::Client,
}

fn main() {
    println!("Hello, world!");
}
