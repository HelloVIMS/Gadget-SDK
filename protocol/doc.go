// Package protocol implements the VIMS Gadget Protocol, version 1 (VGP/1),
// as specified in PROTOCOL.md at the root of this repository.
//
// The package is carrier-agnostic: a [Carrier] moves whole messages (the
// wscarrier package provides WebSocket). On top of it:
//
//   - [ClientHandshake] and [ServerHandshake] run Noise IK and return a
//     [Conn], which encrypts, chunks and reassembles [Frame]s;
//   - [Session] multiplexes calls, results, events and keepalive over a Conn;
//   - [Pairing] encodes and parses pairing URIs;
//   - [Hello] and [Welcome] are the first frame each side sends.
//
// Gadgets use the gadget package, which drives all of this; hosts (the VIMS
// daemon) use this package directly.
package protocol
