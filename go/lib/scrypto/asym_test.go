// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	// Ed25519 test vectors
	// Taken from the Python test vectors: http://ed25519.cr.yp.to/python/sign.input
	Ed25519TestPrivateKey = xtest.MustParseHexString(
		`b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd`)
	Ed25519TestPublicKey = xtest.MustParseHexString(
		`77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb`)
	Ed25519TestMsg = xtest.MustParseHexString(
		`916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171ce18a542b0b7f96c1691a3be60
		31522894a8634183eda38798a0c5d5d79fbd01dd04a8646d71873b77b221998a81922d8105f892316369d5224c99
		83372d2313c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460376d7f3ac22ff372c1
		8f613f2ae2e856af40`)
	Ed25519TestSignature = xtest.MustParseHexString(
		`6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b4eb2ca19ebcf917f0f34200a9e
		dbad3901b64ab09cc5ef7b9bcc3c40c0ff7509`)

	// NaClBox test vectors
	// Taken from the NaCl distribution:
	// https://github.com/jedisct1/libsodium/blob/1.0.16/test/default/box.c
	NaClBoxTestPrivateKey = xtest.MustParseHexString(
		`77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a`)
	NaClBoxTestPublicKey = xtest.MustParseHexString(
		`de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f`)
	NaClBoxTestNonce = xtest.MustParseHexString(`69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37`)
	NaClBoxTestMsg   = xtest.MustParseHexString(
		`be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e
		6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a83
		8f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705`)
	NaClBoxTestCiphertext = xtest.MustParseHexString(
		`f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531
		a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab93216
		4548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a659
		9b1f654cb45a74e355a5`)
)

func TestGenKeyPairs(t *testing.T) {
	t.Run("GenKeyPairs should return a valid Curve25519xSalsa20Poly1305 key pair",
		func(t *testing.T) {
			rawPubkey, rawPrivkey, err := GenKeyPair(Curve25519xSalsa20Poly1305)
			assert.NoError(t, err)
			assert.Len(t, rawPubkey, NaClBoxKeySize)
			assert.Len(t, rawPrivkey, NaClBoxKeySize)
			newPubkey, newPrivkey, err := GenKeyPair(Curve25519xSalsa20Poly1305)
			assert.NoError(t, err)
			assert.NotEqual(t, newPubkey, rawPubkey)
			assert.NotEqual(t, newPrivkey, rawPrivkey)
		})

	t.Run("GenKeyPairs should return a valid Ed25519 key pair", func(t *testing.T) {
		rawPubkey, rawPrivkey, err := GenKeyPair(Ed25519)
		assert.NoError(t, err)
		assert.Len(t, rawPubkey, ed25519.PublicKeySize)
		assert.Len(t, rawPrivkey, ed25519.PrivateKeySize)
		newPubkey, newPrivkey, err := GenKeyPair(Ed25519)
		assert.NoError(t, err)
		assert.NotEqual(t, newPubkey, rawPubkey)
		assert.NotEqual(t, newPrivkey, rawPrivkey)
	})

	t.Run("GenKeyPairs should throw error for unknown algo", func(t *testing.T) {
		_, _, err := GenKeyPair("asdf")
		assert.Error(t, err)
	})
}

func TestSign(t *testing.T) {
	// Note from: https://godoc.org/golang.org/x/crypto/ed25519
	// "...this package's private key representation includes a public key suffix to make
	// multiple signing operations with the same key more efficient...""
	privKey := common.RawBytes(ed25519.NewKeyFromSeed(Ed25519TestPrivateKey))
	t.Run("Sign should sign message correctly", func(t *testing.T) {
		sig, err := Sign(Ed25519TestMsg, privKey, Ed25519)
		assert.NoError(t, err)
		assert.Equal(t, Ed25519TestSignature, sig)
	})

	t.Run("Sign should throw error for invalid key size", func(t *testing.T) {
		_, err := Sign(Ed25519TestMsg, privKey[:63], Ed25519)
		assert.Error(t, err)
	})

	t.Run("Sign should throw error for unknown algo", func(t *testing.T) {
		_, err := Sign(Ed25519TestMsg, privKey, "asdf")
		assert.Error(t, err)
	})
}

func TestVerify(t *testing.T) {
	t.Run("Verify should verify signature correctly", func(t *testing.T) {
		err := Verify(Ed25519TestMsg, Ed25519TestSignature, Ed25519TestPublicKey, Ed25519)
		assert.NoError(t, err)
	})

	t.Run("Verify should throw an error for an invalid signature length", func(t *testing.T) {
		err := Verify(Ed25519TestMsg, Ed25519TestSignature[:63], Ed25519TestPublicKey, Ed25519)
		assert.Error(t, err)
	})

	t.Run("Verify should throw an error for a mangled signature", func(t *testing.T) {
		mangled := append(common.RawBytes{}, Ed25519TestSignature...)
		mangled[0] ^= 0xFF
		err := Verify(Ed25519TestMsg, mangled, Ed25519TestPublicKey, Ed25519)
		assert.Error(t, err)
	})

	t.Run("Verify should throw an error for an invalid key size", func(t *testing.T) {
		err := Verify(Ed25519TestMsg, Ed25519TestSignature, Ed25519TestPublicKey[:31], Ed25519)
		assert.Error(t, err)
	})

	t.Run("Verify should throw an error for unknown algo", func(t *testing.T) {
		err := Verify(Ed25519TestMsg, Ed25519TestSignature, Ed25519TestPublicKey, "asdf")
		assert.Error(t, err)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("Encrypt should encrypt a plaintext correctly", func(t *testing.T) {
		rawCipher, err := Encrypt(NaClBoxTestMsg, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.NoError(t, err)
		assert.Equal(t, NaClBoxTestCiphertext, rawCipher)
	})

	t.Run("Encrypt should throw error for invalid nonce size", func(t *testing.T) {
		_, err := Encrypt(NaClBoxTestMsg, NaClBoxTestNonce[:23], NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Encrypt should throw error for invalid public key size", func(t *testing.T) {
		_, err := Encrypt(NaClBoxTestMsg, NaClBoxTestNonce, NaClBoxTestPublicKey[:31],
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Encrypt should throw error for invalid private key size", func(t *testing.T) {
		_, err := Encrypt(NaClBoxTestMsg, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey[:31], Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Encrypt should throw an error for unknown algo", func(t *testing.T) {
		_, err := Encrypt(NaClBoxTestMsg, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, "asdf")
		assert.Error(t, err)
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Decrypt should decrypt a ciphertex correctly", func(t *testing.T) {
		rawMsg, err := Decrypt(NaClBoxTestCiphertext, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.NoError(t, err)
		assert.Equal(t, NaClBoxTestMsg, rawMsg)
	})

	t.Run("Decrypt should throw error for invalid nonce size", func(t *testing.T) {
		_, err := Decrypt(NaClBoxTestCiphertext, NaClBoxTestNonce[:23], NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Decrypt should throw error for invalid public key size", func(t *testing.T) {
		_, err := Decrypt(NaClBoxTestCiphertext, NaClBoxTestNonce, NaClBoxTestPublicKey[:31],
			NaClBoxTestPrivateKey, Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Decrypt should throw error for invalid private key size", func(t *testing.T) {
		_, err := Decrypt(NaClBoxTestCiphertext, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey[:31], Curve25519xSalsa20Poly1305)
		assert.Error(t, err)
	})

	t.Run("Decrypt should throw an error for unknown algo", func(t *testing.T) {
		_, err := Decrypt(NaClBoxTestCiphertext, NaClBoxTestNonce, NaClBoxTestPublicKey,
			NaClBoxTestPrivateKey, "asdf")
		assert.Error(t, err)
	})
}
