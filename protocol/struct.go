package protocol

import "github.com/csanti/onet"

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

