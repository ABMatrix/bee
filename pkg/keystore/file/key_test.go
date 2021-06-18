package file_test

import (
	"fmt"
	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/keystore/file"
	"testing"
)

func TestKey(t *testing.T) {
	str := "{\"address\":\"8bfe2673d1bc54f7757922eaa3fb0fedfc8ae7a3\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"c2e2fa2997f677932bf02f409a6482367ea97eece9750d3417f25a47c86e4f70\",\"cipherparams\":{\"iv\":\"ad40fb22a5df0f88be53e6ad7d51888e\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"n\":32768,\"r\":8,\"p\":1,\"dklen\":32,\"salt\":\"0697c39ff64b7e0197e38cf61309b45a0a4a269cd524aa62ef27cd861acd77db\"},\"mac\":\"e845d3b2f0714c4bddb175ee147c8cabbdd9874ac19c9052f6cdd6a06a7c2275\"},\"version\":3}"

	var data []byte = []byte(str)
	password := "123456"
	pk, err := file.DecryptKey(data, password)
	if err != nil {
		print(err)
	}
	p := crypto.EncodeSecp256k1PrivateKey(pk)
	fmt.Printf("0x%x", p)
}
