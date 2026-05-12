//go:build linux

package statemachine

// FrameKind enumerates the per-frame kinds Transition dispatches on.
type FrameKind uint8

const (
	FrameKindQuery FrameKind = iota
	FrameKindParse
	FrameKindBind
	FrameKindDescribe
	FrameKindExecute
	FrameKindSync
	FrameKindFlush
	FrameKindClose
	FrameKindTerminate
	FrameKindFunctionCall // Plan 05b live; Plan 05a falls through to default-deny
	FrameKindCopyData
	FrameKindCopyDone
	FrameKindCopyFail
)

// Frame is a thin protocol-level view of one PostgreSQL frontend message.
// The dispatcher constructs concrete adapters from pgproto3.FrontendMessage
// before calling Transition. The state machine does not depend on pgproto3.
type Frame interface {
	Kind() FrameKind
}

type QueryFrame struct {
	SQL string
}

func (*QueryFrame) Kind() FrameKind { return FrameKindQuery }

type ParseFrame struct {
	Name string // empty string is unnamed prepared statement
	SQL  string
}

func (*ParseFrame) Kind() FrameKind { return FrameKindParse }

type BindFrame struct {
	Portal    string
	Statement string // prepared-statement name
}

func (*BindFrame) Kind() FrameKind { return FrameKindBind }

type DescribeFrame struct {
	ObjectType byte // 'S' (statement) or 'P' (portal)
	Name       string
}

func (*DescribeFrame) Kind() FrameKind { return FrameKindDescribe }

type ExecuteFrame struct {
	Portal string
}

func (*ExecuteFrame) Kind() FrameKind { return FrameKindExecute }

type SyncFrame struct{}

func (*SyncFrame) Kind() FrameKind { return FrameKindSync }

type FlushFrame struct{}

func (*FlushFrame) Kind() FrameKind { return FrameKindFlush }

type CloseFrame struct {
	ObjectType byte // 'S' (statement) or 'P' (portal)
	Name       string
}

func (*CloseFrame) Kind() FrameKind { return FrameKindClose }

type TerminateFrame struct{}

func (*TerminateFrame) Kind() FrameKind { return FrameKindTerminate }

type FunctionCallFrame struct {
	FunctionOID uint32
}

func (*FunctionCallFrame) Kind() FrameKind { return FrameKindFunctionCall }

type CopyDataFrame struct {
	Body []byte // borrowed; do not retain past the Transition call
}

func (*CopyDataFrame) Kind() FrameKind { return FrameKindCopyData }

type CopyDoneFrame struct{}

func (*CopyDoneFrame) Kind() FrameKind { return FrameKindCopyDone }

type CopyFailFrame struct {
	Message string
}

func (*CopyFailFrame) Kind() FrameKind { return FrameKindCopyFail }
