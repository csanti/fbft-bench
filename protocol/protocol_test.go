package protocol


import (
	"testing"
	"time"

	"go.dedis.ch/onet"
	"go.dedis.ch/onet/log"
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
	proposal := []byte("new proposal")
	defaultTimeout := 5 * time.Second

	suite := newNetworkSuite()
	test := onet.NewTCPTest(suite)
	defer test.CloseAll()
	_, _, tree := test.GenBigTree(n, n, n-1, true)

	pi, err := test.CreateProtocol(DefaultProtocolName, tree)
	if err != nil {
		test.CloseAll()
		t.Fatal("Error in creation of protocol:", err)
	}

	protocol := pi.(*FbftProtocol)
	protocol.Msg = proposal
	protocol.Timeout = defaultTimeout

	protocol.DistributeKeys()

	log.Lvl1("Sleeping for keys to distribute correctly...")
	time.Sleep(time.Duration(2)*time.Second)

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

	// wait for goroutines to finish gracefully
	time.Sleep(time.Duration(2)*time.Second)
	protocol.Shutdown()
}

