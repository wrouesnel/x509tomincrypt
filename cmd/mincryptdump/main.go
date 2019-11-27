package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"github.com/wrouesnel/x509tomincrypt/pkg/androidrsa"
		"encoding/base64"
	"bytes"
)


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

	dec := base64.NewDecoder(base64.StdEncoding,bytes.NewReader(bytes.Split(certBytes, []byte(" "))[0]))
	data, err := ioutil.ReadAll(dec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading certificate bytes:", err.Error())
		os.Exit(1)
	}

	v := androidrsa.RSAPublicKey{}
	v.FromBytes(data)

	fmt.Println(v)

	os.Exit(0)
}

