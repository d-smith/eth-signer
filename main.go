package main

import (
	"encoding/hex"
	"errors"
	"eth-signer/test"
	"fmt"
	"log"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"golang.org/x/crypto/sha3"
)

var configs map[party.ID]*cmp.Config

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
		addr := PublicKeyBytesToAddress(sigPublicKey)
		fmt.Println("Address from sig public key", addr)
	}

	return nil
}

func main() {
	configs = make(map[party.ID]*cmp.Config)
	ids := party.IDSlice{"a", "b", "c"}
	threshold := 2

	net := test.NewNetwork(ids)

	// Can we reuse the key group config?
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := All(id, ids, threshold, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()

	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := All(id, ids, threshold, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
