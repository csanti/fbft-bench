package protocol

import (
	"go.dedis.ch/onet"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/share"
)

/*
type PrePrepare struct {
	Msg []byte
	Digest []byte
	Sig []byte
	Sender string
}

type StructPrePrepare struct {
	*onet.TreeNode
	PrePrepare
}
*/

type Announce struct {
	Msg []byte
	Digest []byte
	SigShare []byte
	Sender string
}

type StructAnnounce struct {
	*onet.TreeNode
	Announce
}

type Prepare struct {
	Digest []byte
	SigShare []byte
	Sender string
}

type StructPrepare struct {
	*onet.TreeNode
	Prepare
}

type Prepared struct {
	Digest []byte
	AggrSig []byte
	Sender string
}

type StructPrepared struct {
	*onet.TreeNode
	Prepared
}

type Commit struct {
	Digest []byte
	SigShare []byte
	Sender string
}

type StructCommit struct {
	*onet.TreeNode
	Commit
}

type Committed struct {
	Digest []byte
	AggrSig []byte
	Sender string
}

type StructCommitted struct {
	*onet.TreeNode
	Committed
}


type Reply struct {
	Result []byte
	Sig []byte
	Sender string
}

type StructReply struct {
	*onet.TreeNode
	Reply
}

type Config struct {
	Public    []kyber.Point   // to reconstruct public polynomial
	Share     *share.PriShare // private share
}

type StructConfig struct {
	*onet.TreeNode
	Config
}

