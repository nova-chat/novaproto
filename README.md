# novaproto

Wire protocol for [NovaChat](https://github.com/nova-chat). A two-layer binary
codec for end-to-end encrypted messaging: clients seal payloads for each other,
then re-seal the result for the server so it can route without seeing the
plaintext.

## Layout

```
novaproto/
├── novaproto.go          shared constants (Magic, Version, Flag, Options)
├── c2c/                  client↔client end-to-end layer (NovaPacket)
├── c2s/                  client↔server transport layer (NovaServerPacket)
├── internal/frame/       AEAD frame primitive (AES-GCM, header obfuscation,
│                         random prefix, padding)
├── serializer/           reflection-based binary serializer with generics
└── compress/             content-aware zstd helper for payloads
```

The two codec layers stack: a `c2c.NovaPacket` encoded by `c2c.Codec` becomes
the `Payload` of a `c2s.NovaServerPacket` encoded by `c2s.Codec`. Servers only
touch the c2s layer and treat the inner blob as opaque.

Both layers share the same wire header format and AEAD primitive (see
[internal/frame/frame.go](internal/frame/frame.go)). The `c2s` layer
additionally exposes `EncodePlain`/`DecodePlain` for the unencrypted handshake
frames sent before a transport key has been negotiated.

## Install

```sh
go get github.com/nova-chat/novaproto
```

Requires Go 1.25+.

## Usage

### Client→client (end-to-end)

```go
import (
    "github.com/nova-chat/novaproto"
    "github.com/nova-chat/novaproto/c2c"
)

codec, err := c2c.NewCodec(e2eKey, &novaproto.Options{
    PadTo:     64,
    PadMax:    32,
    PrefixMax: 16,
})
if err != nil {
    return err
}

frame, err := codec.Encode(&c2c.NovaPacket{
    Meta:    c2c.Metadata{ContentType: 1, Encrypted: false},
    Payload: []byte("hello"),
})
```

### Client→server (transport)

```go
import (
    "github.com/google/uuid"
    "github.com/nova-chat/novaproto"
    "github.com/nova-chat/novaproto/c2s"
)

codec, err := c2s.NewCodec(transportKey, nil)
if err != nil {
    return err
}

frame, err := codec.Encode(&c2s.NovaServerPacket{
    Meta: c2s.Metadata{
        SenderID:    senderUUID,
        TargetID:    targetUUID,
        MessageType: c2s.MsgData,
        Encrypted:   true,
    },
    Payload: innerC2CFrame,
})
```

During the initial handshake, before a transport key exists, use
`c2s.EncodePlain` / `c2s.DecodePlain`. On the receive side, branch on
`c2s.IsPlain(frame)` to decide which decoder to call.

## Options

`novaproto.Options` tunes traffic-analysis resistance for either layer:

| Field       | Effect                                                      |
|-------------|-------------------------------------------------------------|
| `PadTo`     | Round plaintext body up to a multiple of N bytes            |
| `PadMax`    | Add 0..N uniformly random bytes on top of `PadTo`           |
| `PrefixMax` | Random per-session prefix length, capped (≤ `MaxPrefixLen`) |

All three default to 0 (disabled).

## Tests

```sh
go test ./...
go test -bench=. ./...
```

## License

TBD.
