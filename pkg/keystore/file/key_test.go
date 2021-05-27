package file_test

import (
	"fmt"
	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/keystore/file"
	"testing"
)

func TestKey(t *testing.T) {
	str := "{\"address\":\"1cd0b8184229ebda58f934d7cfa6b1bf313e8fc2\",\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"ad5fed75d46b3810c9ffc2b952ecf3f817b44f9a26e237d49e4f006c57eca955\",\"cipherparams\":{\"iv\":\"ca29ccdd9acf02be393609d110a8c675\"},\"kdf\":\"scrypt\",\"kdfparams\":{\"n\":32768,\"r\":8,\"p\":1,\"dklen\":32,\"salt\":\"bb9c3ea9fe900117b092c4779744946c762504be12b1f01fd7f8f467146e324e\"},\"mac\":\"d6cc922a6813bd196145ef994820742ddc4998899930c618d856925df4ab2ad8\"},\"version\":3}"

	var data []byte = []byte(str)
	password := "123456";
	pk, err := file.DecryptKey(data, password)
	if err != nil {
		print(err)
	}
	p := crypto.EncodeSecp256k1PrivateKey(pk)
	fmt.Printf("0x%x",p)
}