package protocol


import (
	"errors"
	"sync"
	"time"
	"bytes"
	"math"
	"fmt"
	"encoding/json"
//	"strings"

	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/network"
	"go.dedis.ch/kyber/sign/tbls"
	"go.dedis.ch/kyber/share"

//	"go.dedis.ch/kyber/util/random"
	"go.dedis.ch/kyber/pairing/bn256"
//	"go.dedis.ch/kyber/util/random"

	"crypto/sha512"
)

var Suite = bn256.NewSuite()
var G2 = Suite.G2()
// Name can be used from other packages to refer to this protocol.
const DefaultProtocolName = "FBFT"

func init() {
	log.SetDebugVisible(1)
	network.RegisterMessages(Announce{}, Prepare{}, Prepared{}, Commit{}, Committed{}, Reply{})
	onet.GlobalProtocolRegister(DefaultProtocolName, NewProtocol)
}


type VerificationFn func(msg []byte, data []byte) bool

var defaultTimeout = 60 * time.Second

type FbftProtocol struct {
	*onet.TreeNodeInstance

	Msg					[]byte
	Data 				[]byte
	nNodes				int

	FinalReply 			chan []byte
	startChan       	chan bool
	stoppedOnce    		sync.Once
	verificationFn  	VerificationFn
	Timeout 			time.Duration

	PriKeySharesMap		map[string]*share.PriShare
	PubKey 				*share.PubPoly
/*
	ChannelPrePrepare   chan StructPrePrepare
	ChannelPrepare 		chan StructPrepare
	ChannelCommit		chan StructCommit
	ChannelReply		chan StructReply
*/
	ChannelAnnounce		chan StructAnnounce
	ChannelPrepare 		chan StructPrepare
	ChannelPrepared		chan StructPrepared
	ChannelCommit		chan StructCommit
	ChannelCommitted	chan StructCommitted
	ChannelReply		chan StructReply
}

// Check that *fbftProtocol implements onet.ProtocolInstance
var _ onet.ProtocolInstance = (*FbftProtocol)(nil)

// NewProtocol initialises the structure for use in one round
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl1("new protocol")
	netSize := n.Tree().Size()
	threshold := netSize/2 + 1
	//secret := Suite.G1().Scalar()
	priPoly := share.NewPriPoly(Suite.G2(), threshold, nil, Suite.RandomStream())
	pubPoly := priPoly.Commit(Suite.G2().Point().Base())
	//sigShares := make([][]byte, 0)
	allShares := priPoly.Shares(netSize)
	priKeySharesMap := make(map[string]*share.PriShare)
	for i, node := range n.Tree().List() {
		priKeySharesMap[node.ServerIdentity.ID.String()] = allShares[i]
	}
	
	/*
	pubKeysMap := make(map[string]kyber.Point)
	for _, node := range n.Tree().List() {
		//fmt.Println(node.ServerIdentity, node.ServerIdentity.Public, node.ServerIdentity.ID.String())
		pubKeysMap[node.ServerIdentity.ID.String()] = node.ServerIdentity.Public
	}
	*/

	vf := func(msg, data []byte) bool {
		// Simulate verification function by sleeping
		b, _ := json.Marshal(msg)
		m := time.Duration(len(b) / (500 * 1024))  //verification of 150ms per 500KB simulated
		waitTime := 150 * time.Millisecond * m
		log.Lvl3("Verifying for", waitTime)

		// TODO: change if we want to simulate verification time
		//time.Sleep(waitTime)  

		return true 
	}
	//_, commits := public.Info()
	t := &FbftProtocol{
		TreeNodeInstance: 	n,
		nNodes: 			n.Tree().Size(),
		startChan:       	make(chan bool, 1),
		FinalReply:   		make(chan []byte, 1),
		//PubKeysMap:		pubKeysMap,
		PriKeySharesMap:	priKeySharesMap,
		PubKey:				pubPoly,
		Data:            	make([]byte, 0),
		verificationFn:		vf,
	}

	for _, channel := range []interface{}{
		&t.ChannelAnnounce,
		&t.ChannelPrepare,
		&t.ChannelPrepared,
		&t.ChannelCommit,
		&t.ChannelCommitted,
		&t.ChannelReply,
	} {
		err := t.RegisterChannel(channel)
		if err != nil {
			return nil, errors.New("couldn't register channel: " + err.Error())
		}
	}

	return t, nil
}

// Start sends the Announce-message to all children
func (fbft *FbftProtocol) Start() error {
	// TODO verify args not null
	log.Lvl1("Starting FbftProtocol")

	if fbft.IsRoot() {
		// send pre-prepare phase
		digest := sha512.Sum512(fbft.Msg) // TODO digest is correct?
		//sig, err := schnorr.Sign(fbft.Suite(), fbft.Private(), fbft.Msg)

		sigshare, err := tbls.Sign(Suite, fbft.PriKeySharesMap[fbft.ServerIdentity().ID.String()], fbft.Msg)
		if err != nil {
			return err
		}

		go func() {
			if errs := fbft.SendToChildrenInParallel(&Announce{Msg:fbft.Msg, Digest:digest[:], SigShare:sigshare, Sender:fbft.ServerIdentity().ID.String()}); len(errs) > 0 {
				log.Lvl2(fbft.ServerIdentity(), "failed to send announce to all children")
			}
		}()
	}
	
	return nil
}

func (fbft *FbftProtocol) Dispatch() error {

	log.Lvl3(fbft.ServerIdentity(), "Started node")

	nRepliesThreshold := int(math.Ceil(float64(fbft.nNodes - 1 ) * (float64(2)/float64(3)))) + 1
	nRepliesThreshold = min(nRepliesThreshold, fbft.nNodes - 1)
	var futureDigest []byte
	var signedDigest []byte
	if !fbft.IsRoot() {
		// Verification of the data
		verifyChan := make(chan bool, 1)

		// wait for pre-prepare message from leader
		log.Lvl2(fbft.ServerIdentity(), "Waiting for announce")
		announce, channelOpen := <-fbft.ChannelAnnounce
		if !channelOpen {
			return nil
		}
		log.Lvl2(fbft.ServerIdentity(), "Received announce. Verifying...")
		go func() {
			verifyChan <- fbft.verificationFn(announce.Msg, fbft.Data)
		}()

		// Verify the signature for authentication
		//log.Lvlf1("%d - %d",announce.Msg,announce.SigShare)
		//log.Lvl1(fbft.PubKey)
		/*
		err := tbls.Verify(Suite, fbft.PubKey, announce.Msg, announce.SigShare)
		if err != nil {
			return err
		}*/

		// verify message digest
		digest := sha512.Sum512(announce.Msg)
		if !bytes.Equal(digest[:], announce.Digest) {
			log.Lvl3(fbft.ServerIdentity(), "received announce digest is not correct")
		}

		futureDigest = announce.Digest

		ok := <-verifyChan
		if !ok {
			return fmt.Errorf("verification failed on node")
		}
		
		// Sign message and broadcast
		signedDigest, err := tbls.Sign(Suite, fbft.PriKeySharesMap[fbft.ServerIdentity().ID.String()], futureDigest)
		if err != nil {
			return err
		}
		
		// send the message to the root node (leader)
		if err := fbft.SendToParent(&Prepare{Digest:futureDigest, SigShare:signedDigest, Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl3(fbft.ServerIdentity(), "error while broadcasting prepare message")
		}
	}


	prepareTimeout := time.After(defaultTimeout * 2)
	nReceivedPrepareMessages := 0

	if fbft.IsRoot() {
loop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
			case _, channelOpen := <-fbft.ChannelPrepare:
				if !channelOpen {
					return nil
				}
				// Verify the signature for authentication
				/*
				err := tbls.Verify(Suite, fbft.PubKey, prepare.Digest, prepare.SigShare)
				if err != nil {
					return err
				}*/
				nReceivedPrepareMessages++
			case <-prepareTimeout:
				// TODO
				break loop
			}	
		}

		if !(nReceivedPrepareMessages >= nRepliesThreshold) {
			errors.New("node didn't receive enough prepare messages. Stopping.")
		} else {
			log.Lvl2(fbft.ServerIdentity(), "Received enough prepare messages (> 2/3 + 1):", nReceivedPrepareMessages, "/", fbft.nNodes)
		}

		//digest := sha512.Sum512(fbft.Msg)

		// Sign message and broadcast
		// TODO: this should be the aggregated signature
		signedDigest2, err := tbls.Sign(Suite, fbft.PriKeySharesMap[fbft.ServerIdentity().ID.String()], futureDigest)
		if err != nil {
			return err
		}

		// Leader sends prepared to other nodes
		if err := fbft.SendToChildrenInParallel(&Prepared{Digest:futureDigest, Sender:fbft.ServerIdentity().ID.String(), AggrSig:signedDigest2}); err != nil {
			log.Lvl1(fbft.ServerIdentity(), "error while broadcasting prepared message")
		}

	} else {
		log.Lvl2(fbft.ServerIdentity(), "Waiting for prepared")
		_, channelOpen := <-fbft.ChannelPrepared
		if !channelOpen {
			return nil
		}
		log.Lvl2(fbft.ServerIdentity(), "Received prepared. Verifying...")

		// verify aggregated signature
		// send the message to the root node (leader)
		if err := fbft.SendToParent(&Commit{Digest:futureDigest, SigShare:signedDigest, Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl3(fbft.ServerIdentity(), "error while broadcasting commit message")
		}

	}
	commitTimeout := time.After(defaultTimeout * 2)
	nReceivedCommitMessages := 0

	if fbft.IsRoot() {
commitLoop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
			case _, channelOpen := <-fbft.ChannelCommit:
				if !channelOpen {
					return nil
				}

				// Verify the signature for authentication
				/*
				err := tbls.Verify(Suite, fbft.PubKey, commit.Digest, commit.SigShare)
				if err != nil {
					return err
				}*/
				nReceivedCommitMessages++
			case <-commitTimeout:
				// TODO
				break commitLoop
			}
		}

		if !(nReceivedCommitMessages >= nRepliesThreshold) {
			log.Lvl1(fbft.ServerIdentity(), "node didn't receive enough commit messages. Stopping.", nReceivedCommitMessages, " / ", nRepliesThreshold)
			return errors.New("node didn't receive enough commit messages. Stopping.")
		} else {
			log.Lvl1(fbft.ServerIdentity(), "Received enough commit messages (> 2/3 + 1):", nReceivedCommitMessages, "/", fbft.nNodes)
		}

		// aggregate signature again...

		// Leader sends committed to other nodes
		if err := fbft.SendToChildrenInParallel(&Committed{Digest:futureDigest, Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl1(fbft.ServerIdentity(), "error while broadcasting committed message")
		}

	} else {
		log.Lvl2(fbft.ServerIdentity(), "Waiting for committed")
		_, channelOpen := <-fbft.ChannelCommitted
		if !channelOpen {
			return nil
		}
		log.Lvl2(fbft.ServerIdentity(), "Received committed. Verifying...")

		// verify aggregated signature
		// send the message to the root node (leader)
		if err := fbft.SendToParent(&Reply{Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl3(fbft.ServerIdentity(), "error while broadcasting reply message")
		}
	}

	receivedReplies := 0

	if fbft.IsRoot() {
replyLoop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
			case _, channelOpen := <-fbft.ChannelReply:
				if !channelOpen {
					return nil
				}

				// Verify the signature for authentication
				/*
				err := tbls.Verify(Suite, fbft.PubKey, committed.Digest, committed.AggrSig)
				if err != nil {
					return err
				}*/

				receivedReplies++
				log.Lvl2("Leader got one reply, total received is now", receivedReplies, "out of", nRepliesThreshold, "needed.")
				
			case <-time.After(defaultTimeout * 2):
				// wait a bit longer than the protocol timeout
				log.Lvl3("didn't get reply in time")
				break replyLoop
			}
		}

		fbft.FinalReply <- futureDigest[:]

	}

	return nil
}

// Shutdown stops the protocol
func (fbft *FbftProtocol) Shutdown() error {
	fbft.stoppedOnce.Do(func() {
		close(fbft.ChannelAnnounce)
		close(fbft.ChannelPrepare)
		close(fbft.ChannelPrepared)
		close(fbft.ChannelCommit)
		close(fbft.ChannelCommitted)
		close(fbft.ChannelReply)
	})
	return nil
}


func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

/*
func dkg(t, n int) ([]*share.PriShare, *share.PubPoly) {
	allShares := make([][]*share.PriShare, n)
	var public *share.PubPoly
	for i := 0; i < n; i++ {
		priPoly := share.NewPriPoly(G2, t, nil, random.New())
		allShares[i] = priPoly.Shares(n)
		if public == nil {
			public = priPoly.Commit(G2.Point().Base())
			continue
		}
		public, _ = public.Add(priPoly.Commit(G2.Point().Base()))
	}
	shares := make([]*share.PriShare, n)
	for i := 0; i < n; i++ {
		v := G2.Scalar().Zero()
		for j := 0; j < n; j++ {
			v = v.Add(v, allShares[j][i].V)
		}
		shares[i] = &share.PriShare{I: i, V: v}
	}
	return shares, public
}
*/