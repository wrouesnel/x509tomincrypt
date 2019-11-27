package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"crypto/rsa"
	"math/big"
	"encoding/base64"
	"os/user"
	"github.com/wrouesnel/x509tomincrypt/pkg/androidrsa"
)

const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)


// reverseBytes reverses the order of bytes in a buffer, and returns the
// edited buffer.
func reverseBytes(a []byte) []byte {
	for i := len(a)/2-1; i >= 0; i-- {
		opp := len(a)-1-i
		a[i], a[opp] = a[opp], a[i]
	}
	return a
}

// PaddedBigBytes encodes a big integer as a big-endian byte slice. The length
// of the slice is at least n bytes.
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

func main() {
	var err error
	var certBytes []byte
	if len(os.Args) > 1 {
		if f, err := os.Open(os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "Error reading certificate from file:", os.Args, err.Error())
			os.Exit(1)
		} else {
			certBytes, err = ioutil.ReadAll(f)
			_ = f.Close()
		}
	} else {
		certBytes, err = ioutil.ReadAll(os.Stdin)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading certificate bytes:", err.Error())
		os.Exit(1)
	}
	// Read *exactly* one certificate
	block, _ := pem.Decode(certBytes)

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decoding certificate:", err.Error())
		os.Exit(1)
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "Parsed file was not an RSA private key")
		os.Exit(1)
	}

	// Convert to mincrypt format. Algorithm from
	// https://android.googlesource.com/platform/system/extras/+/8d7e924/verity/generate_verity_key.c
	// but encoding from https://android.googlesource.com/platform/system/core/+/master/libcrypto_utils/android_pubkey.c

	keyStruct := androidrsa.RSAPublicKey{}

	if privateKey.Size() != androidrsa.AndroidPubKeyModulusSize {
		fmt.Fprintln(os.Stderr, "ADB requires an RSA key of 2048 bits length exactly.")
		os.Exit(1)
	}

	// Store the modulus size
	keyStruct.Modulus_size_words = androidrsa.AndroidPubKeyModulusSizeWords

	n := new(big.Int).Set(privateKey.N)

	// Compute and store n0inv = -1 / N[0] mod 2^32.
	r32 := new(big.Int).SetBit(new(big.Int), 32, 1)
	n0inv := new(big.Int).Mod(n, r32)
	n0inv.ModInverse(n0inv, r32)
	n0inv.Sub(r32, n0inv)

	keyStruct.N0inv = uint32(n0inv.Uint64())

	// Note: byte-reversal is to order things little-endian as expected by Android
	// big.Int.Bytes() in Go returns them as big-endian.

	// Store the modulus
	copy(keyStruct.Modulus[:], reverseBytes(PaddedBigBytes(n,androidrsa.AndroidPubKeyModulusSize)))

	// Compute and store rr = (2^(rsa_size)) ^ 2 mod N.

	// Store rr
	rr := new(big.Int).SetBit(new(big.Int), androidrsa.AndroidPubKeyModulusSize * 8, 1)
	rr.Exp(rr,big.NewInt(2), n)
	copy(keyStruct.Rr[:], reverseBytes(PaddedBigBytes(rr,androidrsa.AndroidPubKeyModulusSize)))

	// Store the exponent
	keyStruct.Exponent = uint32(privateKey.E)

	enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	enc.Write(keyStruct.Bytes())
	enc.Close()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	username := "unknown"
	user, err := user.Current()
	if err == nil {
		username = user.Username
	}

	os.Stdout.WriteString(fmt.Sprintf(" %s@%s", username, hostname))

	os.Exit(0)
}

