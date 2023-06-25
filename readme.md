# Sign an Ethereum transactions using MPC TSS

## Running a Node

Use the script in run-a-node 

This will create the following accounts...

```
Available Accounts
==================
(0) 0x892BB2e4F6b14a2B5b82Ba8d33E5925D42D4431F (1000 ETH)
(1) 0x9949f7e672a568bB3EBEB777D5e8D1c1107e96E5 (1000 ETH)
(2) 0x835F0Aa692b8eBCdEa8E64742e5Bce30303669c2 (1000 ETH)
(3) 0x7bA7d161F9E8B707694f434d65c218a1F0853B1C (1000 ETH)
(4) 0xB4C3D79CDC0eb7A8576a8bf224Bbc6Bec790c320 (1000 ETH)
(5) 0x5Ad35F89D8C1d03089BDe2578Ce43883E3f2A7B0 (1000 ETH)
(6) 0x0234643975F308b76d1241897e7d70b02C155daa (1000 ETH)
(7) 0x5199524B11e801c52161CA76dB9BFD72f4a4E1E1 (1000 ETH)
(8) 0x549381D65fe61046911d11743D5c0941Ed704640 (1000 ETH)
(9) 0x73dA1eD554De26C467d97ADE090af6d52851745E (1000 ETH)

Private Keys
==================
(0) 0xcb1a18dff8cfcee16202bf86f1f89f8b3881107b8192cd06836fda9dbc0fde1b
(1) 0xa54f24f80839b659fc44fbb19492507bc734ea572f6f5672787cd8e9a198bf28
(2) 0x824f9e081f93102ca26e9e696bb6804079a5e4e3fca3a05216e2b6e0538fcab9
(3) 0x3e56e9b2db8389123a03816c37dd4515e07077483fbe865156a2d8f6003b6725
(4) 0xca55c5904f97405816f8d24c5e7810aaec2aa347ea0e1f920f19eca05669ae7b
(5) 0x6100006a16d6a0fd065f62165e64d412920afd0e8fc59956ad7a9116e363b72e
(6) 0x55b0e7919eb08e618dbddf025341094eefc0db60244736c1faac1412d68868f3
(7) 0x81b475051c4686cffe815e50216a9bac397c0e5d9108170823b290d41823fa8a
(8) 0xc3599ced1484dc8eccbb477cf8c318ca48ef1f2aac81a10a3774fe40d3b678de
(9) 0xf9832eeac47db42efeb2eca01e6479bfde00fda8fdd0624d45efd0e4b9ddcd3b

```

To run commands via the truffle console:

```
truffle console --url http://127.0.0.1:8545

let balance = await web3.eth.getBalance('0xcb95df7f187b374947E499f6C0047E76e0812468')

 let txHash = await web3.eth.sendTransaction({from: accounts[0], to: '0x43f336E88D21C912c57e5C44bD52eb1d5CD204f2', value: 10 });

```

1st experiment - code will have to mainstate of key shares 
2nd - can we persist and restore? Yep - stick the configs in a map
3rd - save the presigs as well?
4th - sign with minimal set of shares based on theshold

Initial go set up

```
go mod init ethsigner
go get github.com/taurusgroup/multi-party-sig@a0b25d3
```

Initial truffle set up

```
npm install -g truffle
truffle init
truffle console --url http://127.0.0.1:8545
 ```
