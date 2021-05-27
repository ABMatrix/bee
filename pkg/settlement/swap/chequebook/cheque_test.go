// Copyright 2020 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chequebook_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethersphere/bee/pkg/crypto"
	"github.com/ethersphere/bee/pkg/crypto/eip712"
	signermock "github.com/ethersphere/bee/pkg/crypto/mock"
	"github.com/ethersphere/bee/pkg/settlement/swap/chequebook"

	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/core/types"
	crypt "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
)

func TestSignCheque(t *testing.T) {
	chequebookAddress := common.HexToAddress("0x8d3766440f0d7b949a5e32995d09619a7f86e632")
	beneficiaryAddress := common.HexToAddress("0xb8d424e9662fe0837fb1d728f1ac97cebb1085fe")
	signature := common.Hex2Bytes("abcd")
	cumulativePayout := big.NewInt(10)
	chainId := int64(1)
	cheque := &chequebook.Cheque{
		Chequebook:       chequebookAddress,
		Beneficiary:      beneficiaryAddress,
		CumulativePayout: cumulativePayout,
	}

	signer := signermock.New(
		signermock.WithSignTypedDataFunc(func(data *eip712.TypedData) ([]byte, error) {

			if data.Message["beneficiary"].(string) != beneficiaryAddress.Hex() {
				t.Fatal("signing cheque with wrong beneficiary")
			}

			if data.Message["chequebook"].(string) != chequebookAddress.Hex() {
				t.Fatal("signing cheque for wrong chequebook")
			}

			if data.Message["cumulativePayout"].(string) != cumulativePayout.String() {
				t.Fatal("signing cheque with wrong cumulativePayout")
			}

			return signature, nil
		}),
	)

	chequeSigner := chequebook.NewChequeSigner(signer, chainId)

	result, err := chequeSigner.Sign(cheque)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, signature) {
		t.Fatalf("returned wrong signature. wanted %x, got %x", signature, result)
	}
}

func TestSignChequeIntegration(t *testing.T) {
	//{"chequebookaddress":"0x10CA5e1675DEa2F3DfBB83Cd32555cB3ba510D26"} sydney chequebookAddress
	chequebookAddress := common.HexToAddress("0x10CA5e1675DEa2F3DfBB83Cd32555cB3ba510D26")

	//0x2791e31c2f5dd0512609f29bbd7a64035d896769 london beneficiaryAddress
	beneficiaryAddress := common.HexToAddress("0x2791e31c2f5dd0512609f29bbd7a64035d896769")
	cumulativePayout := big.NewInt(500000000)
	chainId := int64(1)
                                    //15df7324807502ffb407574698fbbeb82a270f0c9e192c56fea593b001afd9c1 sydney peivkey
	data, err := hex.DecodeString("15df7324807502ffb407574698fbbeb82a270f0c9e192c56fea593b001afd9c1")
	if err != nil {
		t.Fatal(err)
	}

	privKey, err := crypto.DecodeSecp256k1PrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewDefaultSigner(privKey)

	cheque := &chequebook.Cheque{
		Chequebook:       chequebookAddress,
		Beneficiary:      beneficiaryAddress,
		CumulativePayout: cumulativePayout,
	}

	chequeSigner := chequebook.NewChequeSigner(signer, chainId)

	result, err := chequeSigner.Sign(cheque)
	if err != nil {
		t.Fatal(err)
	}

	println("bytes: ",result)

	signed := &chequebook.SignedCheque{
		*cheque,
		result,
	}

	encodedfakeCheque, err := json.Marshal(signed)
	bb := make([]byte, hex.EncodedLen(len(encodedfakeCheque)))
	hex.Encode(bb,encodedfakeCheque)

	fmt.Printf("fake3 cheque bytes: %s \n", bb)
	println("fake1 cheque bytes: ", string(encodedfakeCheque))
	fmt.Printf("fake2 cheque bytes: %v \n", encodedfakeCheque)


	// london {"chequebookaddress":"0x10285243B2258f74F4703C0F1a28EB6624e333f6"} london chequebookaddress
	recipient := common.HexToAddress("0x10285243B2258f74F4703C0F1a28EB6624e333f6")
	callData, err := chequebookABI.Pack("cashChequeBeneficiary", recipient, cheque.CumulativePayout, signed.Signature)

	callData_out := make([]byte, hex.EncodedLen(len(callData)))
	hex.Encode(callData_out,callData)
	println("callData_out: ", string(callData_out))

	//request := &transaction.TxRequest{
	//	To:       &chequebookAddress,
	//	Data:     callData,
	//	GasPrice: big.NewInt(500),
	//	GasLimit: 300000,
	//	Value:    big.NewInt(0),
	//}


	//types.NewContractCreation(
	//	nonce,
	//	request.Value,
	//	gasLimit,
	//	gasPrice,
	//	request.Data,
	//)
}

var chequebookAddress = "" //sydney chequebook  付钱的
var beneficiaryAdd = "" // london chequebook    捡钱的
var issuerPrivKey = "" // sydney privkey 付钱私钥

func fakeCheque() []byte {
	chequebookAddress := common.HexToAddress(chequebookAddress)

	beneficiaryAddress := common.HexToAddress(beneficiaryAdd)
	cumulativePayout := big.NewInt(990000000000000000)
	chainId := int64(1)

	privateKey, err := crypt.HexToECDSA(issuerPrivKey)

	signer := crypto.NewDefaultSigner(privateKey)

	cheque := &chequebook.Cheque{
		Chequebook:       chequebookAddress,
		Beneficiary:      beneficiaryAddress,
		CumulativePayout: cumulativePayout,
	}

	chequeSigner := chequebook.NewChequeSigner(signer, chainId)

	result, err := chequeSigner.Sign(cheque)
	if err != nil {
		print(err)
	}

	println("bytes: ",result)

	signed := &chequebook.SignedCheque{
		*cheque,
		result,
	}

	encodedfakeCheque, err := json.Marshal(signed)
	bb := make([]byte, hex.EncodedLen(len(encodedfakeCheque)))
	hex.Encode(bb,encodedfakeCheque)

	println("fake1 cheque bytes: ", string(encodedfakeCheque))

	recipient := common.HexToAddress(beneficiaryAdd)
	callData, err := chequebookABI.Pack("cashChequeBeneficiary", recipient, cheque.CumulativePayout, signed.Signature)

	callData_out := make([]byte, hex.EncodedLen(len(callData)))
	hex.Encode(callData_out,callData)
	println("callData_out: ", string(callData_out))
	return callData
}

func TestSend(t *testing.T) {
	client, err := ethclient.Dial("https://goerli..io/v3/")
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypt.HexToECDSA(issuerPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypt.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(0) // in wei (1 eth)
	gasLimit := uint64(200000)                // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	gasPrice = big.NewInt(550)

	toAddress := common.HexToAddress(chequebookAddress)
	var data []byte
	data = fakeCheque()
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", tx.Hash().Hex())
}

func TestWithdraw(t *testing.T) {
	client, err := ethclient.Dial("https://goerli.infura.io/v3/")
	if err != nil {
		log.Fatal(err)
	}

	//london
	privateKey, err := crypt.HexToECDSA("")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	fromAddress := crypt.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(0) // in wei (1 eth)
	gasLimit := uint64(100000)                // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	gasPrice = big.NewInt(550)

	// london book
	toAddress := common.HexToAddress("")
	var data []byte
	callData, err := chequebookABI.Pack("withdraw", 990000000000000000)
	data = callData
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", tx.Hash().Hex())
}