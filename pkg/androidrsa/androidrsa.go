package androidrsa

import (
	"bytes"
	"encoding/binary"
)

const AndroidPubKeyModulusSize = 256
const AndroidPubKeyModulusSizeWords = AndroidPubKeyModulusSize / 4

// Android RSAPublicKey format
type RSAPublicKey struct {
	// Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
	Modulus_size_words uint32
	// Precomputed montgomery parameter: -1 / n[0] mod 2^32
	N0inv uint32
	// RSA modulus as a little-endian array.
	Modulus [AndroidPubKeyModulusSize]uint8
	// Montgomery parameter R^2 as a little-endian array of little-endian words.
	Rr [AndroidPubKeyModulusSize]uint8
	// RSA modulus: 3 or 65537
	Exponent uint32
}

func (pkey *RSAPublicKey) Bytes() []byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, pkey.Modulus_size_words)
	binary.Write(buf, binary.LittleEndian, pkey.N0inv)
	binary.Write(buf, binary.LittleEndian, pkey.Modulus)
	binary.Write(buf, binary.LittleEndian, pkey.Rr)
	binary.Write(buf, binary.LittleEndian, pkey.Exponent)
	return buf.Bytes()
}

func (pkey *RSAPublicKey) FromBytes(b []byte) {
	buf := bytes.NewReader(b)
	binary.Read(buf, binary.LittleEndian, &pkey.Modulus_size_words)
	binary.Read(buf, binary.LittleEndian, &pkey.N0inv)
	binary.Read(buf, binary.LittleEndian, &pkey.Modulus)
	binary.Read(buf, binary.LittleEndian, &pkey.Rr)
	binary.Read(buf, binary.LittleEndian, &pkey.Exponent)
}
