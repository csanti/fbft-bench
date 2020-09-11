package protocol


import (
	"testing"
	"time"

	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"go.dedis.ch/kyber/pairing"
	"go.dedis.ch/kyber"
)
type networkSuite struct {
	kyber.Group
	pairing.Suite
}

func newNetworkSuite() *networkSuite {
	return &networkSuite{
		Group: Suite.G2(),
		Suite: Suite,
	}
}

func TestNode(t *testing.T) {
	log.SetDebugVisible(2)
	n := 10
	proposal := []byte("dedis")
	defaultTimeout := 5 * time.Second
/*
	local := onet.NewLocalTest(Suite)
	//_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes - 1, true)
	_, _, tree := local.GenTree(10, true)
	*/
	suite := newNetworkSuite()
	test := onet.NewTCPTest(suite)
	defer test.CloseAll()
	_, _, tree := test.GenBigTree(n, n, 9, true)

	pi, err := test.CreateProtocol(DefaultProtocolName, tree)
	if err != nil {
		test.CloseAll()
		t.Fatal("Error in creation of protocol:", err)
	}

	protocol := pi.(*FbftProtocol)
/*
	netSize := 10
	threshold := netSize/2 + 1
	secret := Suite.G1().Scalar().Pick(Suite.RandomStream())
	priPoly := share.NewPriPoly(Suite.G2(), threshold, secret, Suite.RandomStream())
	pubPoly := priPoly.Commit(Suite.G2().Point().Base())
	allShares := priPoly.Shares(netSize)
	priKeySharesMap := make(map[string]*share.PriShare)
	for i, node := range tree.List() {
		priKeySharesMap[node.ServerIdentity.ID.String()] = allShares[i]
	}
	protocol.PriKeySharesMap = priKeySharesMap
	protocol.PubKey = pubPoly
	*/
	protocol.Msg = proposal
	protocol.Timeout = defaultTimeout
	protocol.DistributeKeys()
	log.Lvl1("Sleeping for keys to distribute correctly...")
	time.Sleep(time.Duration(4)*time.Second)
	err = protocol.Start()
	if err != nil {
		test.CloseAll()
		t.Fatal(err)
	}

	select {
	case finalReply := <-protocol.FinalReply:
		log.Lvl1("Leader sent final reply")
		_ = finalReply
	case <-time.After(defaultTimeout * 2):
		t.Fatal("Leader never got enough final replies, timed out")
	}

	time.Sleep(time.Duration(4)*time.Second)

	
}

