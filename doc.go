// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package securecookie encodes and decodes authenticated and encrypted
// cookie values.
//
// Cookie values are serialized (JSON by default), sealed together with a
// timestamp using XChaCha20-Poly1305, and base64-encoded. The cookie name
// is bound to the ciphertext as additional authenticated data, so a value
// issued for one cookie name cannot be replayed under another. The
// timestamp is validated against MinAge/MaxAge before the payload is
// deserialized.
//
// Basic usage:
//
//	key := securecookie.GenerateRandomKey(32) // persist this somewhere!
//	s, err := securecookie.New(key, nil)
//	if err != nil {
//		// ...
//	}
//
//	// Encode a value into a cookie.
//	encoded, err := s.Encode("session", map[string]string{"user": "42"})
//
//	// Decode it back.
//	value := map[string]string{}
//	ts, err := s.Decode("session", encoded, &value)
//
// To rotate keys, pass the previous keys in Options.RotatedKeys. New
// cookies are always encrypted with the primary key; rotated keys are only
// tried when decoding, so cookies issued before the rotation stay valid
// until they expire:
//
//	s, err := securecookie.New(newKey, &securecookie.Options{
//		RotatedKeys: [][]byte{oldKey},
//	})
package securecookie
