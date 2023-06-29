package main

import (
	"context"
	"encoding/hex"
	"errors"
	"eth-signer/test"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"golang.org/x/crypto/sha3"

	"github.com/manifoldco/promptui"
)

var configs map[party.ID]*cmp.Config
var walletAddress common.Address
var ethClient ethclient.Client
var signedMessage []byte

func PublicKeyBytesToAddress(publicKey []byte) common.Address {
	var buf []byte

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey[1:]) // remove EC prefix 04
	buf = hash.Sum(nil)
	address := buf[12:]

	return common.HexToAddress(hex.EncodeToString(address))
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	fmt.Println("running key gen for ", id)
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *test.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
	if err != nil {
		return nil, err
	}

	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	preSignature := signResult.(*ecdsa.PreSignature)
	if err = preSignature.Validate(); err != nil {
		return nil, errors.New("failed to verify cmp presignature")
	}
	return preSignature, nil
}

func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *test.Network, pl *pool.Pool) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)
	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify cmp signature")
	}

	//sigEth, err := signature.SigEthereum()
	//fmt.Println("presign online eth sig from ", c.ID, " is ", hexutil.Encode(sigEth))

	//sigPublicKey, err := crypto.Ecrecover(m, sigEth)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("presign online public key from sig is", hexutil.Encode(sigPublicKey))

	return signature, nil
}

func All(id party.ID, ids party.IDSlice, threshold int, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// CMP KEYGEN

	if configs[id] == nil {
		fmt.Println("cmp keygen")
		config, err := CMPKeygen(id, ids, threshold, n, pl)
		if err != nil {
			return err
		}

		configs[id] = config
	}
	keygenConfig := configs[id]

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP PRESIGN
	fmt.Println("cmp presign")
	preSignature, err := CMPPreSign(keygenConfig, signers, n, pl)
	if err != nil {
		return nil
	}

	messageToSign := []byte("hello")
	hash := crypto.Keccak256Hash(messageToSign)

	// CMP PRESIGN ONLINE
	fmt.Println("cmp presign online")
	signature, err := CMPPreSignOnline(keygenConfig, preSignature, hash.Bytes(), n, pl)
	if err != nil {
		return err
	}

	if id == "a" {
		sigEth, err := signature.SigEthereum()
		if err != nil {
			return err
		}

		sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), sigEth)
		if err != nil {
			log.Fatal(err)
		}

		// Grab the address as the last 20 bytes of the public key
		// from the sig
		walletAddress = PublicKeyBytesToAddress(sigPublicKey)
		fmt.Println("Address from sig public key", walletAddress)
	}

	return nil
}

func Sign(msg []byte, id party.ID, ids party.IDSlice, threshold int, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// CMP KEYGEN

	if configs[id] == nil {
		fmt.Println("cmp keygen")
		config, err := CMPKeygen(id, ids, threshold, n, pl)
		if err != nil {
			return err
		}

		configs[id] = config
	}
	keygenConfig := configs[id]

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP PRESIGN
	fmt.Println("cmp presign")
	preSignature, err := CMPPreSign(keygenConfig, signers, n, pl)
	if err != nil {
		return nil
	}

	// CMP PRESIGN ONLINE
	fmt.Println("cmp presign online")
	signature, err := CMPPreSignOnline(keygenConfig, preSignature, msg, n, pl)
	if err != nil {
		return err
	}

	sigEth, err := signature.SigEthereum()
	if err != nil {
		return err
	}

	signedMessage = sigEth

	sigPublicKey, err := crypto.Ecrecover(msg, sigEth)
	if err != nil {
		log.Fatal(err)
	}

	// Grab the address as the last 20 bytes of the public key
	// from the sig
	walletAddress = PublicKeyBytesToAddress(sigPublicKey)
	fmt.Println("Address from signed message public key", id, "=>", walletAddress)

	return nil
}

func CreateKeyShares(id party.ID, ids party.IDSlice, threshold int, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// CMP KEYGEN

	if configs[id] == nil {
		fmt.Println("cmp keygen")
		config, err := CMPKeygen(id, ids, threshold, n, pl)
		if err != nil {
			return err
		}

		configs[id] = config
	}

	fmt.Println("key share for id", id, configs[id].ECDSA)

	return nil
}

type partyFunc func(party.ID, party.IDSlice, int, *test.Network, *sync.WaitGroup, *pool.Pool) error

func runFuncForAllParties(fn partyFunc, wg *sync.WaitGroup, ids party.IDSlice, threshold int, n *test.Network) {

	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := fn(id, ids, threshold, n, wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}

type signPartyFunc func([]byte, party.ID, party.IDSlice, int, *test.Network, *sync.WaitGroup, *pool.Pool) error

func runSignFuncForAllParties(fn signPartyFunc, msg []byte, wg *sync.WaitGroup, ids party.IDSlice, threshold int, n *test.Network) {

	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := fn(msg, id, ids, threshold, n, wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}

func main() {
	ethClient, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		fmt.Println(err)
		return
	}

	configs = make(map[party.ID]*cmp.Config)
	ids := party.IDSlice{"a", "b", "c"}
	threshold := 2

	net := test.NewNetwork(ids)

	// Create the key shares
	var wg sync.WaitGroup

	runFuncForAllParties(CreateKeyShares, &wg, ids, threshold, net)

	runFuncForAllParties(All, &wg, ids, threshold, net)

	prompt := promptui.Select{
		Label: "Did you send more than 1 ETH to " + walletAddress.String(),
		Items: []string{"yep", "nope"},
	}

	_, result, err := prompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	if result == "nope" {
		fmt.Println("you are dead to me")
		return
	}

	fmt.Println("we'll see about that...")
	balance, err := ethClient.BalanceAt(context.Background(), walletAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Balance", balance)

	var minEth big.Int
	minEth.SetString("1", 10)
	minInWei := new(big.Int).Mul(&minEth, big.NewInt(params.Ether))
	fmt.Println(minInWei.String())
	if balance.Cmp(minInWei) < 0 {
		fmt.Println("you are dead to me")
		return
	}

	// Prompt for send of eth
	fmt.Println("Ok... where should I send some ETH?")
	addressPrompt := promptui.Prompt{
		Label: "Address",
	}

	destAddr, err := addressPrompt.Run()

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	toAddress := common.HexToAddress(destAddr)

	fmt.Println("Allright sending to", destAddr)

	fmt.Println("Let's check the dest balance before...")
	balance, err = ethClient.BalanceAt(context.Background(), toAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Balance", balance)

	nonce, err := ethClient.PendingNonceAt(context.Background(), walletAddress)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Nonce", nonce)

	value := big.NewInt(1000000000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)                // in units
	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("gas price", gasPrice)

	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainId := big.NewInt(1337) // TODO what's the right way to obtain this dynamically?
	signer := types.NewEIP155Signer(chainId)

	hash := signer.Hash(tx)
	fmt.Println("hash to sign is", hash)

	runSignFuncForAllParties(Sign, hash.Bytes(), &wg, ids, threshold, net)

	fmt.Printf("%+v", tx)

	// Send txn...
	fmt.Println("create signed txn")
	signedTx, err := tx.WithSignature(signer, signedMessage)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("send txn")
	err = ethClient.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Let's check the dest balance after...")
	balance, err = ethClient.BalanceAt(context.Background(), toAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Balance", balance)

}
