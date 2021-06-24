package main

import (
	"errors"
	"fmt"
	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/keystore/file"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
)

var (
	keyFilePath string // flag variable, key file
	password    string // flag variable, password of keystore
	show        bool   // flag variable, show private key
)

// Check the password
func Check(cmd *cobra.Command, args []string) (err error) {
	if keyFilePath == "" {
		return errors.New("no file path")
	}
	if password == "" {
		return errors.New("no password")
	}

	data, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return err
	}

	pk, err := file.DecryptKey(data, password)
	if err != nil {
		return err
	}

	if show {
		p := crypto.EncodeSecp256k1PrivateKey(pk)
		fmt.Printf("0x%x\n", p)
	}

	return nil
}

func main() {
	// usage:  bee-keystore -f ./swarm.key -p 123 -v
	c := &cobra.Command{
		Use:          "check ",
		Short:        "Check the password",
		Long:         `Check that the keystore and password match`,
		RunE:         Check,
		SilenceUsage: true,
	}

	c.Flags().StringVarP(&keyFilePath, "file", "f", "", "the swarm.key file")
	c.Flags().StringVarP(&password, "password", "p", "", "password of keystore")
	c.Flags().BoolVarP(&show, "show", "v", false, "password of keystore")
	c.SetOutput(c.OutOrStdout())
	err := c.Execute()
	if err != nil {
		os.Exit(1)
	}
}
