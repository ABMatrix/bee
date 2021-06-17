// Copyright 2020 The Swarm Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chequebook

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethersphere/bee/pkg/settlement/swap/transaction"
	"github.com/ethersphere/go-sw3-abi/sw3abi"
	"github.com/ethersphere/sw3-bindings/v3/simpleswapfactory"
	"golang.org/x/net/context"
)

var (
	GoerliChainID              = int64(5)
	GoerliFactoryAddress       = common.HexToAddress("0x73c412512E1cA0be3b89b77aB3466dA6A1B9d273")
	GoerliLegacyFactoryAddress = common.HexToAddress("0xf0277caffea72734853b834afc9892461ea18474")
	XDaiChainID                = int64(100)
	XDaiFactoryAddress         = common.HexToAddress("0xc2d5a532cf69aa9a1378737d8ccdef884b6e7420")
)

var (
	ErrInvalidFactory       = errors.New("not a valid factory contract")
	ErrNotDeployedByFactory = errors.New("chequebook not deployed by factory")
	errDecodeABI            = errors.New("could not decode abi data")

	factoryABI                  = transaction.ParseABIUnchecked(sw3abi.SimpleSwapFactoryABIv0_4_0)
	simpleSwapDeployedEventType = factoryABI.Events["SimpleSwapDeployed"]
)

// Factory is the main interface for interacting with the chequebook factory.
type Factory interface {
	// ERC20Address returns the token for which this factory deploys chequebooks.
	ERC20Address(ctx context.Context) (common.Address, error)
	// Deploy deploys a new chequebook and returns once the transaction has been submitted.
	Deploy(ctx context.Context, issuer common.Address, defaultHardDepositTimeoutDuration *big.Int, nonce common.Hash) (common.Hash, error)
	// WaitDeployed waits for the deployment transaction to confirm and returns the chequebook address
	WaitDeployed(ctx context.Context, txHash common.Hash) (common.Address, error)
	// VerifyBytecode checks that the factory is valid.
	VerifyBytecode(ctx context.Context) error
	// VerifyChequebook checks that the supplied chequebook has been deployed by this factory.
	VerifyChequebook(ctx context.Context, chequebook common.Address) error
}

type factory struct {
	backend            transaction.Backend
	transactionService transaction.Service
	address            common.Address
	legacyAddresses    []common.Address // addresses of old factories which were allowed for deployment
}

type simpleSwapDeployedEvent struct {
	ContractAddress common.Address
}

// NewFactory creates a new factory service for the provided factory contract.
func NewFactory(backend transaction.Backend, transactionService transaction.Service, address common.Address, legacyAddresses []common.Address) Factory {
	return &factory{
		backend:            backend,
		transactionService: transactionService,
		address:            address,
		legacyAddresses:    legacyAddresses,
	}
}

// Deploy deploys a new chequebook and returns once the transaction has been submitted.
func (c *factory) Deploy(ctx context.Context, issuer common.Address, defaultHardDepositTimeoutDuration *big.Int, nonce common.Hash) (common.Hash, error) {
	callData, err := factoryABI.Pack("deploySimpleSwap", issuer, big.NewInt(0).Set(defaultHardDepositTimeoutDuration), nonce)
	if err != nil {
		return common.Hash{}, err
	}

	request := &transaction.TxRequest{
		To:       &c.address,
		Data:     callData,
		GasPrice: nil,
		GasLimit: 0,
		Value:    big.NewInt(0),
	}

	txHash, err := c.transactionService.Send(ctx, request)
	if err != nil {
		return common.Hash{}, err
	}

	return txHash, nil
}

// WaitDeployed waits for the deployment transaction to confirm and returns the chequebook address
func (c *factory) WaitDeployed(ctx context.Context, txHash common.Hash) (common.Address, error) {
	receipt, err := c.transactionService.WaitForReceipt(ctx, txHash)
	if err != nil {
		return common.Address{}, err
	}

	var event simpleSwapDeployedEvent
	err = transaction.FindSingleEvent(&factoryABI, receipt, c.address, simpleSwapDeployedEventType, &event)
	if err != nil {
		return common.Address{}, fmt.Errorf("contract deployment failed: %w", err)
	}

	return event.ContractAddress, nil
}

// the bytecode of factories which can be used for deployment
var currentDeployVersion []byte = common.FromHex(sw3abi.SimpleSwapFactoryDeployedBinv0_4_0)

// the bytecode of factories from which we accept chequebooks
var supportedVersions = [][]byte{
	currentDeployVersion,
	common.FromHex(sw3abi.SimpleSwapFactoryDeployedBinv0_3_1),
}

// VerifyBytecode checks that the factory is valid.
func (c *factory) VerifyBytecode(ctx context.Context) (err error) {
	code, err := c.backend.CodeAt(ctx, c.address, nil)
	if err != nil {
		return err
	}

	if !bytes.Equal(code, currentDeployVersion) {
		return ErrInvalidFactory
	}

LOOP:
	for _, factoryAddress := range c.legacyAddresses {
		code, err := c.backend.CodeAt(ctx, factoryAddress, nil)
		if err != nil {
			return err
		}

		for _, referenceCode := range supportedVersions {
			if bytes.Equal(code, referenceCode) {
				continue LOOP
			}
		}

		return fmt.Errorf("failed to find matching bytecode for factory %x: %w", factoryAddress, ErrInvalidFactory)
	}

	return nil
}

// VerifyChequebook checks that the supplied chequebook has been deployed by this factory.
func (c *factory) VerifyChequebook(ctx context.Context, chequebook common.Address) error {
	callData, err := factoryABI.Pack("deployedContracts", chequebook)
	if err != nil {
		return err
	}

	output, err := c.transactionService.Call(ctx, &transaction.TxRequest{
		To:   &c.address,
		Data: callData,
	})
	if err != nil {
		return err
	}

	results, err := factoryABI.Unpack("deployedContracts", output)
	if err != nil {
		return err
	}

	if len(results) != 1 {
		return errDecodeABI
	}

	deployed, ok := abi.ConvertType(results[0], new(bool)).(*bool)
	if !ok || deployed == nil {
		return errDecodeABI
	}
	if !*deployed {
		return ErrNotDeployedByFactory
	}
	return nil
}

// ERC20Address returns the token for which this factory deploys chequebooks.
func (c *factory) ERC20Address(ctx context.Context) (common.Address, error) {
	callData, err := factoryABI.Pack("ERC20Address")
	if err != nil {
		return common.Address{}, err
	}

	output, err := c.transactionService.Call(ctx, &transaction.TxRequest{
		To:   &c.address,
		Data: callData,
	})
	if err != nil {
		return common.Address{}, err
	}

	results, err := factoryABI.Unpack("ERC20Address", output)
	if err != nil {
		return common.Address{}, err
	}

	if len(results) != 1 {
		return common.Address{}, errDecodeABI
	}

	erc20Address, ok := abi.ConvertType(results[0], new(common.Address)).(*common.Address)
	if !ok || erc20Address == nil {
		return common.Address{}, errDecodeABI
	}
	return *erc20Address, nil
}

// DiscoverFactoryAddress returns the canonical factory for this chainID
func DiscoverFactoryAddress(chainID int64) (currentFactory common.Address, legacyFactories []common.Address, found bool) {
	switch chainID {
	case GoerliChainID:
		// goerli
		return GoerliFactoryAddress, []common.Address{
			GoerliLegacyFactoryAddress,
		}, true
	case XDaiChainID:
		// xdai
		return XDaiFactoryAddress, []common.Address{}, true
	default:
		return common.Address{}, nil, false
	}
}
