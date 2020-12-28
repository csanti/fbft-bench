package protocol


import (
	"errors"
	"sync"
	"time"
	"bytes"
	"math"
	"fmt"
	"encoding/json"

	"github.com/csanti/onet"
	"github.com/csanti/onet/log"
	"github.com/csanti/onet/network"
	"go.dedis.ch/kyber/sign/tbls"
	"go.dedis.ch/kyber/sign/bls"
	"go.dedis.ch/kyber/share"

	"go.dedis.ch/kyber/pairing/bn256"
	"go.dedis.ch/kyber/util/random"

	"crypto/sha512"
)

var Suite = bn256.NewSuite()
var G2 = Suite.G2()
// Name can be used from other packages to refer to this protocol.
const DefaultProtocolName = "FBFT"

func init() {
	network.RegisterMessages(Announce{}, Prepare{}, Prepared{}, Commit{}, Committed{}, Reply{}, Config{})
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

	PriKeyShare			*share.PriShare
	PubKey 				*share.PubPoly

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

	vf := func(msg, data []byte) bool {
		// Simulate verification function by sleeping
		b, _ := json.Marshal(msg)
		m := time.Duration(len(b) / (500 * 1024))  //verification of 150ms per 500KB simulated
		waitTime := 150 * time.Millisecond * m
		log.Lvl3("Verifying for", waitTime)

		return true 
	}

	t := &FbftProtocol{
		TreeNodeInstance: 	n,
		nNodes: 			n.Tree().Size(),
		startChan:       	make(chan bool, 1),
		FinalReply:   		make(chan []byte, 1),
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

	err := t.RegisterHandler(t.ConfigHandler)
	if err != nil {
		return nil, errors.New("couldn't register handler: " + err.Error())
	}

	return t, nil
}

// Start sends the Announce-message to all children
func (fbft *FbftProtocol) Start() error {
	log.Lvl1("Starting FbftProtocol")

	if fbft.IsRoot() {
		// send pre-prepare phase
		digest := sha512.Sum512(fbft.Msg)
		sigshare, err := tbls.Sign(Suite, fbft.PriKeyShare, fbft.Msg)
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
	log.Lvl3("Sleeping dispatch for keys")
	time.Sleep(time.Duration(4)*time.Second)

	nRepliesThreshold := int(math.Ceil(float64(fbft.nNodes - 1 ) * (float64(2)/float64(3)))) + 1
	nRepliesThreshold = min(nRepliesThreshold, fbft.nNodes - 1)

	var proposalDigest, signedDigest []byte
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
		err := tbls.Verify(Suite, fbft.PubKey, announce.Msg, announce.SigShare)
		if err != nil {
			return err
		}

		// verify message digest
		digest := sha512.Sum512(announce.Msg)
		if !bytes.Equal(digest[:], announce.Digest) {
			log.Lvl3(fbft.ServerIdentity(), "received announce digest is not correct")
		}

		proposalDigest = announce.Digest

		ok := <-verifyChan
		if !ok {
			return fmt.Errorf("verification failed on node")
		}
		
		// Sign message and broadcast
		signedDigest, err := tbls.Sign(Suite, fbft.PriKeyShare, proposalDigest)
		if err != nil {
			return err
		}
		
		// send the message to the root node (leader)
		if err := fbft.SendToParent(&Prepare{Digest:proposalDigest, SigShare:signedDigest, Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl3(fbft.ServerIdentity(), "error while broadcasting prepare message")
		}
	} else {
		digest := sha512.Sum512(fbft.Msg)
		proposalDigest = digest[:]
	}

	prepareTimeout := time.After(defaultTimeout * 2)
	nReceivedPrepareMessages := 0
	validPrepareShares := make([][]byte, 0, nRepliesThreshold)

	if fbft.IsRoot() {
		// first, append own signature
		leaderShare, err := tbls.Sign(Suite, fbft.PriKeyShare, proposalDigest)
		if err != nil {
			return err
		}
		validPrepareShares = append(validPrepareShares, leaderShare)
		nReceivedPrepareMessages++
loop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
			case prepare, channelOpen := <-fbft.ChannelPrepare:
				if !channelOpen {
					return nil
				}
				// Verify the signature for authentication
				err := tbls.Verify(Suite, fbft.PubKey, prepare.Digest, prepare.SigShare)
				if err != nil {
					return err
				}

				validPrepareShares = append(validPrepareShares, prepare.SigShare)
				nReceivedPrepareMessages++
			case <-prepareTimeout:
				// TODO
				break loop
			}	
		}
		if !(nReceivedPrepareMessages >= nRepliesThreshold) {
			errors.New("node didn't receive enough prepare messages. Stopping.")
		} else {
			log.Lvl1(fbft.ServerIdentity(), "Received enough prepare messages (> 2/3 + 1):", nReceivedPrepareMessages, "/", fbft.nNodes)
		}

		// TODO: aggregate signatures, and digest should be from prepared message, not proposaldigest

		// Leader sends prepared to other nodes
		if err := fbft.SendToChildrenInParallel(&Prepared{Digest:proposalDigest, Sender:fbft.ServerIdentity().ID.String(), AggrSig:leaderShare}); err != nil {
			log.Lvl1(fbft.ServerIdentity(), "error while broadcasting prepared message")
		}

	} else {
		log.Lvl2(fbft.ServerIdentity(), "Waiting for prepared")
		prepared, channelOpen := <-fbft.ChannelPrepared
		if !channelOpen {
			return nil
		}
		log.Lvl2(fbft.ServerIdentity(), "Received prepared. Verifying...")

		// verify aggregated signature
		err := tbls.Verify(Suite, fbft.PubKey, prepared.Digest, prepared.AggrSig)
		if err != nil {
			return err
		}
		
		// TODO: change proposaldigest

		// sign and send the message to the root node (leader)
		signedDigest, err := tbls.Sign(Suite, fbft.PriKeyShare, proposalDigest)
		if err != nil {
			return err
		}

		if err := fbft.SendToParent(&Commit{Digest:proposalDigest, SigShare:signedDigest, Sender:fbft.ServerIdentity().ID.String()}); err != nil {
			log.Lvl3(fbft.ServerIdentity(), "error while broadcasting commit message")
		}

	}

	commitTimeout := time.After(defaultTimeout * 2)
	nReceivedCommitMessages := 0
	validCommitShares := make([][]byte, 0, nRepliesThreshold)

	if fbft.IsRoot() {
		// TODO: change for signatuer of commit message
		leaderShare, err := tbls.Sign(Suite, fbft.PriKeyShare, proposalDigest)
		if err != nil {
			return err
		}
		validCommitShares = append(validCommitShares, signedDigest)
		nReceivedCommitMessages++
commitLoop:
		for  i := 0; i <= nRepliesThreshold - 1; i++  {
			select {
			case commit, channelOpen := <-fbft.ChannelCommit:
				if !channelOpen {
					return nil
				}
				// Verify the signature for authentication
				err := tbls.Verify(Suite, fbft.PubKey, commit.Digest, commit.SigShare)
				if err != nil {
					log.Lvl1("Error verifying signature")
					return err
				}

				validCommitShares = append(validCommitShares, commit.SigShare)
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

		// TODO: aggregate signatures again, change proposalDigest and leadershare...

		// Leader sends committed to other nodes
		if err := fbft.SendToChildrenInParallel(&Committed{Digest:proposalDigest, Sender:fbft.ServerIdentity().ID.String(), AggrSig: leaderShare}); err != nil {
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

				receivedReplies++
				log.Lvl2("Leader got one reply, total received is now", receivedReplies, "out of", nRepliesThreshold, "needed.")
				
			case <-time.After(defaultTimeout * 2):
				// wait a bit longer than the protocol timeout
				log.Lvl3("didn't get reply in time")
				break replyLoop
			}
		}

		fbft.FinalReply <- proposalDigest[:]
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

func (fbft *FbftProtocol) ConfigHandler(c StructConfig) error {
	log.Lvl3("Received config")
	fbft.PubKey = share.NewPubPoly(G2, G2.Point().Base(), c.Public)
	fbft.PriKeyShare = c.Share

	return nil
}

func (fbft *FbftProtocol) DistributeKeys() {
	log.Lvl1("Distributing Keys...")
	nRepliesThreshold := int(math.Ceil(float64(fbft.nNodes - 1 ) * (float64(2)/float64(3)))) + 1
	nRepliesThreshold = min(nRepliesThreshold, fbft.nNodes - 1)
	log.Lvlf1("Generating keys for with: %d network size, %d threshold",fbft.nNodes, nRepliesThreshold)
	shares, public := dkg(nRepliesThreshold, fbft.nNodes)
	_, commits := public.Info()

	// save key localy
	count := 0
	fbft.PubKey = share.NewPubPoly(G2, G2.Point().Base(), commits)
	fbft.PriKeyShare = shares[count]

	for _, child := range fbft.Children() {
		c := &Config{
			Public: commits,
			Share: shares[count], 
		}
		if err := fbft.SendTo(child, c); err != nil {
			log.Lvl1(fbft.ServerIdentity(), "error while sending keys")
		}
		count++
	}
}

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

func recover(public *share.PubPoly, msg []byte, sigs [][]byte, t, n int) ([]byte, error) {
	pubShares := make([]*share.PubShare, 0)
	for _, sig := range sigs {
		s := tbls.SigShare(sig)
		i, err := s.Index()
		if err != nil {
			return nil, err
		}
		if err = bls.Verify(Suite, public.Eval(i).V, msg, s.Value()); err != nil {
			return nil, err
		}
		point := Suite.G1().Point()
		if err := point.UnmarshalBinary(s.Value()); err != nil {
			return nil, err
		}
		pubShares = append(pubShares, &share.PubShare{I: i, V: point})
		if len(pubShares) >= t {
			break
		}
	}
	commit, err := share.RecoverCommit(Suite.G1(), pubShares, t, n)
	if err != nil {
		return nil, err
	}
	sig, err := commit.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return sig, nil
}
