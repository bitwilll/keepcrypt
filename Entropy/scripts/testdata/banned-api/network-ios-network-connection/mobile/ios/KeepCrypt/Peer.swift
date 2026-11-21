// iOS 26 adds connections without the NW prefix.
let link = NetworkConnection(to: .hostPort(host: "h", port: 1)) { TCP() }
