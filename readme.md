# Sign an Ethereum transactions using MPC TSS

1st experiment - code will have to mainstate of key shares 
2nd - can we persist and restore? Yep - stick the configs in a map
3rd - save the presigs as well?
4th - sign with minimal set of shares based on theshold

go mod init ethsigner
go get github.com/taurusgroup/multi-party-sig@a0b25d3