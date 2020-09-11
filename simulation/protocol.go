package simulation

/*
The simulation-file can be used with the `cothority/simul` and be run either
locally or on deterlab. Contrary to the `test` of the protocol, the simulation
is much more realistic, as it tests the protocol on different nodes, and not
only in a test-environment.

The Setup-method is run once on the client and will create all structures
and slices necessary to the simulation. It also receives a 'dir' argument
of a directory where it can write files. These files will be copied over to
the simulation so that they are available.

The Run-method is called only once by the root-node of the tree defined in
Setup. It should run the simulation in different rounds. It can also
measure the time each run takes.

In the Node-method you can read the files that have been created by the
'Setup'-method.
*/

import (
	"fmt"
	"time"
//	"errors"
	"math/rand"

	"github.com/BurntSushi/toml"
	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/simul/monitor"
	"github.com/csanti/fbft-bench/protocol"
)

func init() {
	onet.SimulationRegister("FBFT", NewSimulationProtocol)
}

// SimulationProtocol implements onet.Simulation.
type SimulationProtocol struct {
	onet.SimulationBFTree
	NNodes				int
	FailingSubleaders	int
	FailingLeafs		int
	LoadBlock           bool
	BlockSize			int // in bytes
}

// NewSimulationProtocol is used internally to register the simulation (see the init()
// function above).
func NewSimulationProtocol(config string) (onet.Simulation, error) {
	es := &SimulationProtocol{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup implements onet.Simulation.
func (s *SimulationProtocol) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}


// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *SimulationProtocol) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

var proposal = []byte("dedis")
var defaultTimeout = 120 * time.Second

// Run implements onet.Simulation.
func (s *SimulationProtocol) Run(config *onet.SimulationConfig) error {
	log.SetDebugVisible(1)

	var binaryBlock []byte
	binaryBlock = make([]byte, s.BlockSize)
	rand.Read(binaryBlock)
	
	size := config.Tree.Size()
	log.Lvl1("Size is:", size, "rounds:", s.Rounds)
	log.Lvl1("Simulating for", s.Hosts, "nodes in ", s.Rounds, "round")

	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		var fullRound *monitor.TimeMeasure
		if round > 0 {
			fullRound = monitor.NewTimeMeasure("fullRound")
		}

		pi, err := config.Overlay.CreateProtocol(protocol.DefaultProtocolName, config.Tree, onet.NilServiceID)
		if err != nil {
			return err
		}

		fbftPprotocol := pi.(*protocol.FbftProtocol)
		fbftPprotocol.Msg = binaryBlock
		fbftPprotocol.Timeout = defaultTimeout

		err = fbftPprotocol.Start()
		if err != nil {
			return err
		}

		select {
		case finalReply := <-fbftPprotocol.FinalReply:
			log.Lvl1("Leader sent final reply")
			_ = finalReply
		case <-time.After(defaultTimeout * 2):
			fmt.Errorf("Leader never got enough final replies, timed out")
		}
		if round > 0 {
			fullRound.Record()
		}
	}
	return nil
}


func (s *SimulationProtocol) DistributeConfig(config *onet.SimulationConfig) {
	shares, public := dkg((s.Hosts/3)+1, s.Hosts)
	_ = len(config.Roster.List)
	_, commits := public.Info()
	for i, _ := range config.Roster.List {
		_ = &protocol.Config{
			Public: commits,
			Share: shares[i], 
		}
		/*
		if i == 0 {
			config.GetService(fbft.Name).(*fbft.Nfinity).SetConfig(c)
		} else {
			config.Server.Send(si, c)
		}*/
	}
}


