# novaproto

Stream-based transport protocol for [NovaChat](https://github.com/nova-chat),
built around a single TCP connection per client. Provides framing,
per-frame transport encryption, packet multiplexing, routing metadata,
and end-to-end encrypted / compressed sessions for user-to-user traffic
relayed through a shared server.

## Layers

Each layer wraps the one below it and implements a narrow interface so
higher layers stay transport-agnostic. From the bytes on TCP up to the
application:

```
                              TCP
                               ↑
                        NovaWireStream          — framing: reads/writes
                               ↑                  individual FrameHeader
                                                  + content blocks
                        NovaWireStreamCipher     — transport encryption
                               ↑                  with K_cs (AES-GCM),
                                                  per-frame seal, XOR
                                                  header obfuscation,
                                                  late-key installation
                        PacketStream            — packet multiplexing:
                               ↑                  groups frames by
                                                  PacketNonce into logical
                                                  packets, terminates on
                                                  IsTerminating frame
                        RoutedPacketStream      — writes/reads PacketHeader
                               ↑                  as the first bytes of
                                                  each packet body; the
                                                  server uses TargetID
                                                  to route
                        session.Session         — e2e wrapper over one
                               ↑                  RoutedPacketStream for
                                                  one peer: zlib streaming
                                                  compression + chunked
                                                  AES-GCM with K_cc
                          application
```

Two independent encryption keys live in the stack:

| Key     | Scope              | Where it lives              | Who has it            |
|---------|--------------------|-----------------------------|-----------------------|
| `K_cs`  | Transport per hop  | `NovaWireStreamCipher`      | client and server     |
| `K_cc`  | End-to-end per peer| `session.Session`           | only the two peers    |

The server always has `K_cs` for each connected client (one per hop,
derived via the handshake). It decrypts wire frames, reads
`PacketHeader`, and decides:

- `TargetID == uuid.Nil` — packet is for the server itself; handled
  locally.
- `TargetID != uuid.Nil` — packet is for another client; opaque bytes
  (compressed + e2e-sealed with `K_cc`, unknown to the server) are
  streamed to the target via a new `RoutedPacketStream.SendPacket` on
  the outgoing side, re-wrapped with that link's `K_cs`.

## Core types

### `novaproto` (root package)

- **`FrameHeader`** — fixed 18-byte header on every frame: magic,
  content size, frame nonce, packet nonce, `IsTerminating`,
  `IsEncrypted`.
- **`PacketHeader`** — 44-byte header at the start of every packet
  body: magic, `TargetID`, `SourceID`, `Kind` (`uint64`, caller-defined
  message type).
- **`Wire`** / **`PacketRW`** — interfaces satisfied by the concrete
  frame-level and packet-level streams so higher layers can be written
  against abstractions.
- **`NovaWireStream`** — raw framing over any `io.ReadWriter`. Reads
  one frame at a time with `ReadFrame` / `WriteFrame`. No encryption.
- **`NovaWireStreamCipher`** — wraps a `Wire` with optional AES-GCM.
  `SetKey(key)` installs the transport key; before that, frames pass
  through in the clear. Per-frame `IsEncrypted` flag allows mixing
  plain handshake frames and encrypted payload frames on the same
  stream.
- **`PacketStream`** — multiplexes logical packets over a `Wire`. A
  packet is a run of frames sharing one `PacketNonce`, terminated by a
  frame with `IsTerminating=true`. `SendPacket()` returns a streaming
  `io.WriteCloser`, `ReceivePacket()` returns a streaming `io.Reader`.
- **`RoutedPacketStream`** — thin wrapper over `PacketRW` that writes
  / reads a `PacketHeader` as the first bytes of each packet. This is
  the only layer the server understands for routing.

### `novaproto/session`

- **`Session`** — an end-to-end encrypted conversation with one peer.
  Combines `zlib` streaming compression + chunked AES-GCM with the
  shared `K_cc` + `RoutedPacketStream.SendPacket` with the peer's UUID.
  Exposes both byte-array and streaming APIs for send and receive.

### `novaproto/serializer`

- Generic reflection-based binary serializer used throughout the
  project for fixed-layout structs (`FrameHeader`, `PacketHeader`,
  `dhellman.HelloMessage`, etc.). Supports primitives, fixed-size
  arrays, slices, structs, and pointers. No maps, interfaces,
  channels, or functions.

### `novaproto/dhellman`

- X25519 Diffie–Hellman key exchange (via `crypto/ecdh`) plus
  HKDF-SHA256 key derivation (via `crypto/hkdf`). Used to derive both
  `K_cs` (with the server) and `K_cc` (with a peer, handshake tunneled
  through the server). Does not authenticate — callers must layer
  identity verification on top to prevent MITM.

### `novaproto/compress`

- One-shot zlib batch helpers. The `session` package uses
  `compress/zlib` directly for streaming; this package is for
  convenience when the caller has a whole blob in memory.

## Install

```sh
go get github.com/nova-chat/novaproto
```

Requires Go 1.25+ (uses `crypto/hkdf` from stdlib).

## Usage

### Client setup

```go
import (
    "github.com/google/uuid"
    "github.com/nova-chat/novaproto"
    "github.com/nova-chat/novaproto/session"
)

// 1. Open TCP and wrap in the framing layer.
conn, _ := net.Dial("tcp", "chat.example.com:443")
wire := novaproto.NewNovaWireStream(conn)

// 2. Transport cipher — starts without a key so the handshake can
//    run in the clear. SetKey is called once the client and server
//    have derived K_cs via dhellman.
wireCipher := novaproto.NewNovaWireStreamCipher(wire)

// ... do handshake over plain frames, derive K_cs, then ...
wireCipher.SetKey(Kcs)

// 3. Packet multiplexing + routing header.
rps := novaproto.NewRoutedPacketStream(
    novaproto.NewPacketStream(wireCipher),
)

// 4. One Session per peer. Keys come from a peer-to-peer handshake
//    relayed through the server (outside the scope of this snippet).
mySessionWithAlice, _ := session.New(rps, myID, aliceID, Kcc_alice)
mySessionWithBob,   _ := session.New(rps, myID, bobID,   Kcc_bob)
```

### Sending a packet to the server (control / API call)

No Session involved: the server is the endpoint.

```go
w, err := rps.SendPacket(novaproto.PacketHeader{
    TargetID: uuid.Nil,      // Nil → "for the server"
    SourceID: myID,
    Kind:     KindSubscribe, // application-defined
})
if err != nil { ... }
_, _ = w.Write(subscribeRequestBytes)
_ = w.Close()
```

### Sending a small message to another user (end-to-end)

```go
err := mySessionWithAlice.Send(KindChatMessage, []byte("привет, Alice"))
```

Under the hood: plaintext → zlib → chunked AES-GCM(K_cc_alice) →
`RoutedPacketStream.SendPacket(PacketHeader{TargetID: alice, SourceID:
me, Kind: KindChatMessage})` → frames → transport cipher K_cs → TCP.

### Streaming a large payload to another user

```go
w, err := mySessionWithBob.SendStream(KindFileTransfer)
if err != nil { ... }
_, _ = io.Copy(w, bigFile) // 2 GB, streamed through the whole stack
_ = w.Close()
```

Memory footprint per connection stays bounded: ~32 KiB zlib window +
64 KiB AEAD chunk + up to 1 MiB wire frame, regardless of `bigFile`
size.

### Receive loop with demultiplexing

```go
sessions := map[uuid.UUID]*session.Session{
    aliceID: mySessionWithAlice,
    bobID:   mySessionWithBob,
}

for {
    hdr, r, err := rps.ReceivePacket()
    if err != nil {
        // io.EOF → connection closed, other errors → protocol issue
        return
    }

    // Server-originated messages (push notifications, control, etc.)
    if hdr.TargetID == uuid.Nil {
        handleControl(hdr, r)
        continue
    }

    // Incoming user-to-user message from hdr.SourceID
    s, ok := sessions[hdr.SourceID]
    if !ok {
        // Unknown peer — drain and drop so the wire stays in sync.
        io.Copy(io.Discard, r)
        continue
    }

    // Small message variant:
    payload, err := s.OpenBytes(r)
    if err != nil { continue }
    handleMessage(hdr.Kind, payload)

    // Large payload variant — stream straight into a file:
    //   plainR, err := s.OpenStream(r)
    //   io.Copy(out, plainR)
}
```

The caller **must** drain each returned reader to `io.EOF` before
calling `ReceivePacket` again — the underlying `io.Pipe` provides
back-pressure and won't advance until the previous packet is consumed.

### Server dispatch loop

```go
// One RoutedPacketStream per connected client.
for {
    hdr, r, err := clientRPS.ReceivePacket()
    if err != nil { return err }

    if hdr.TargetID == uuid.Nil {
        // API call for us.
        handleControl(clientID, hdr, r)
        continue
    }

    // Relay to another client. Opaque bytes — server doesn't know K_cc.
    target, ok := sessions[hdr.TargetID]
    if !ok {
        io.Copy(io.Discard, r)
        continue
    }

    outW, err := target.rps.SendPacket(novaproto.PacketHeader{
        TargetID: hdr.TargetID,
        SourceID: hdr.SourceID, // preserve so the recipient knows sender
        Kind:     hdr.Kind,
    })
    if err != nil { continue }
    _, _ = io.Copy(outW, r) // streaming relay, no buffering
    _ = outW.Close()
}
```

## Handshake (sketch)

Both `K_cs` and `K_cc` are derived with `dhellman`:

1. Client opens a plain connection to the server, both sides run
   `dhellman.GenerateKeyPair`, exchange `HelloMessage{PublicKey}` as
   plain wire frames (`wireCipher.SetKey` not called yet).
2. Both sides call `KeyPair.ComputeShared(peerPub)` then
   `dhellman.DeriveKey(shared, salt, info)` with matching `salt` and
   `info` to get `K_cs`. Both call `wireCipher.SetKey(Kcs)` — from now
   on all frames are transport-encrypted.
3. For each new peer the client wants to talk to e2e, it runs another
   `dhellman` exchange **through the server**: the `HelloMessage`es
   travel as `RoutedPacketStream` packets with `TargetID = peer`.
   The server relays them opaquely as described above. Both peers
   derive `K_cc` from their DH result. Both construct a
   `session.New(rps, self, peer, Kcc)` and start exchanging
   application messages through it.

`dhellman` does not authenticate the exchange. Identity binding
(signed Hello, long-term keys, TOFU, etc.) is the caller's
responsibility.

## Design notes

- **Routing header is never e2e-encrypted.** `PacketHeader` is always
  visible to the server after it removes the transport cipher layer —
  otherwise it couldn't route user-relay traffic. Server privacy
  comes from `K_cs`; end-to-end content secrecy comes from `K_cc`
  (which the server does not possess).
- **Compression lives above encryption.** `session.Session` runs zlib
  before AES-GCM so the cipher sees high-entropy input and the
  compressor benefits from plaintext redundancy. CRIME-class attacks
  apply if adversary-controlled text is mixed with secrets in the
  same packet — consider this when designing application-level
  message formats.
- **Streaming all the way down.** No layer buffers more than one
  chunk / one frame in memory. A 2 GiB packet flows linearly through
  the stack without materialising anywhere.
- **Per-chunk AEAD with truncation detection.** `session` seals 64 KiB
  chunks with per-chunk nonce `[baseNonce(8) | be32(chunkIdx)]` and
  authenticates a `final` flag as AAD, so truncation attacks (dropping
  tail chunks) are caught. A fresh random base nonce is drawn for
  every outgoing packet.
- **Late-key installation.** Both `NovaWireStreamCipher` and
  `session.Session` can be constructed before their keys are known.
  Wire cipher passes frames through plain until `SetKey`; Session
  can't encrypt without a key at construction time, but the
  surrounding stack (wire, packet, routed) remains usable for the
  handshake.

## Testing

```sh
go test ./...
```

All packages ship tests including streaming round-trips, tamper
rejection, key-mismatch, and large-payload exercises.

## License

TBD.
