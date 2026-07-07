# securecookie

[![Go Reference](https://pkg.go.dev/badge/github.com/libtnb/securecookie.svg)](https://pkg.go.dev/github.com/libtnb/securecookie)

securecookie encodes and decodes authenticated and encrypted cookie values.

It is a modernized fork of [gorilla/securecookie](https://github.com/gorilla/securecookie):
instead of HMAC signing with optional AES-CTR encryption, cookie values are
always sealed with the [XChaCha20-Poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)
AEAD, with the cookie name bound as additional authenticated data and the
issue timestamp encrypted alongside the payload.

## Install

```sh
go get github.com/libtnb/securecookie
```

## Usage

Keys must be exactly 32 bytes. Generate one once and persist it — a new key
on every restart invalidates all previously issued cookies.

```go
key := securecookie.GenerateRandomKey(32)

s, err := securecookie.New(key, nil) // nil means securecookie.DefaultOptions
if err != nil {
    log.Fatal(err)
}

// Encode.
encoded, err := s.Encode("session", map[string]string{"user": "42"})

// Decode. Returns the timestamp at which the cookie was encoded.
value := map[string]string{}
ts, err := s.Decode("session", encoded, &value)
```

### Options

```go
s, err := securecookie.New(key, &securecookie.Options{
    RotatedKeys: [][]byte{oldKey}, // previous keys, tried when decoding
    MinAge:      0,                // reject cookies newer than this, in seconds (0 = off)
    MaxAge:      86400 * 30,       // reject cookies older than this, in seconds (0 = off)
    MaxLength:   4096,             // maximum encoded length, in bytes (0 = off)
    Serializer:  securecookie.JSONEncoder{}, // or GobEncoder{} / NopEncoder{}
})
```

### Key rotation

Pass previous keys in `RotatedKeys` to keep already-issued cookies valid
after switching to a new primary key. Rotated keys are only used for
decoding — new cookies are always encrypted with the primary key.

## Security model

- Confidentiality and integrity via XChaCha20-Poly1305 with a random
  24-byte nonce per cookie.
- The cookie name is authenticated as additional data, so a value cannot be
  replayed under a different cookie name.
- The issue timestamp is sealed inside the ciphertext and checked against
  `MinAge`/`MaxAge` before the payload is deserialized.

## License

BSD licensed, see [LICENSE](LICENSE).
