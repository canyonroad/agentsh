//go:build integration

package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// TestExecPipeline_AllowResumes tests that an allow policy maps to ExecDecisionResume.
func TestExecPipeline_AllowResumes(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "allow",
		effectiveDecision: "allow",
	}, "agentsh-stub.exe")

	req := &SuspendedProcessRequest{
		SessionToken: 0xDEADBEEF,
		ProcessId:    4567,
		ParentId:     1234,
		CreateTime:   1000000,
		ImagePath:    `C:\Windows\System32\cmd.exe`,
		CommandLine:  `cmd.exe /c echo hello`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionResume {
		t.Errorf("allow policy should map to ExecDecisionResume, got %d", decision)
	}
}

// TestExecPipeline_DenyTerminates tests that a deny policy maps to ExecDecisionTerminate.
func TestExecPipeline_DenyTerminates(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "deny",
		effectiveDecision: "deny",
	}, "agentsh-stub.exe")

	req := &SuspendedProcessRequest{
		ProcessId:   4567,
		ImagePath:   `C:\malware.exe`,
		CommandLine: `malware.exe --bad`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionTerminate {
		t.Errorf("deny policy should map to ExecDecisionTerminate, got %d", decision)
	}
}

// TestExecPipeline_ApproveRedirects tests that an approve policy maps to ExecDecisionRedirect.
func TestExecPipeline_ApproveRedirects(t *testing.T) {
	handler := NewWinExecHandler(&mockExecPolicyChecker{
		decision:          "approve",
		effectiveDecision: "approve",
	}, "agentsh-stub.exe")

	req := &SuspendedProcessRequest{
		ProcessId:   4567,
		ImagePath:   `C:\tools\git.exe`,
		CommandLine: `git push origin main`,
	}

	decision := handler.HandleSuspended(req)
	if decision != ExecDecisionRedirect {
		t.Errorf("approve policy should map to ExecDecisionRedirect, got %d", decision)
	}
}

// TestExecPipeline_DriverMessageRoundtrip tests encoding a MsgProcessSuspended message,
// calling handleSuspendedProcess, and verifying the handler receives correct fields
// and the reply is MsgResumeProcess with the correct request ID.
func TestExecPipeline_DriverMessageRoundtrip(t *testing.T) {
	dc := NewDriverClient()

	var gotReq *SuspendedProcessRequest
	dc.SetSuspendedProcessHandler(func(req *SuspendedProcessRequest) ExecDecision {
		gotReq = req
		return ExecDecisionResume
	})

	// Build a MsgProcessSuspended message
	const maxPath = 520
	const maxCmdLine = 2048
	msgSize := 16 + 8 + 4 + 4 + 8 + 8 + (maxPath * 2) + (maxCmdLine * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgProcessSuspended)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 42) // requestId

	// Body
	binary.LittleEndian.PutUint64(msg[16:24], 0xCAFEBABE)   // sessionToken
	binary.LittleEndian.PutUint32(msg[24:28], 5678)          // processId
	binary.LittleEndian.PutUint32(msg[28:32], 1234)          // parentId
	binary.LittleEndian.PutUint64(msg[32:40], 9999)          // createTime
	binary.LittleEndian.PutUint64(msg[40:48], 0)             // padding

	// ImagePath as UTF-16LE
	imgPath := `C:\Windows\notepad.exe`
	imgRunes := utf16.Encode([]rune(imgPath))
	for i, r := range imgRunes {
		binary.LittleEndian.PutUint16(msg[48+i*2:], r)
	}

	// CommandLine as UTF-16LE
	cmdLine := `notepad.exe test.txt`
	cmdRunes := utf16.Encode([]rune(cmdLine))
	cmdOffset := 48 + maxPath*2
	for i, r := range cmdRunes {
		binary.LittleEndian.PutUint16(msg[cmdOffset+i*2:], r)
	}

	reply := make([]byte, 24)
	replyLen := dc.handleSuspendedProcess(msg, reply)

	// Verify handler was called with correct fields
	if gotReq == nil {
		t.Fatal("handler was not called")
	}
	if gotReq.SessionToken != 0xCAFEBABE {
		t.Errorf("sessionToken = 0x%X, want 0xCAFEBABE", gotReq.SessionToken)
	}
	if gotReq.ProcessId != 5678 {
		t.Errorf("processId = %d, want 5678", gotReq.ProcessId)
	}
	if gotReq.ParentId != 1234 {
		t.Errorf("parentId = %d, want 1234", gotReq.ParentId)
	}
	if gotReq.CreateTime != 9999 {
		t.Errorf("createTime = %d, want 9999", gotReq.CreateTime)
	}
	if gotReq.ImagePath != imgPath {
		t.Errorf("imagePath = %q, want %q", gotReq.ImagePath, imgPath)
	}
	if gotReq.CommandLine != cmdLine {
		t.Errorf("commandLine = %q, want %q", gotReq.CommandLine, cmdLine)
	}

	// Verify reply
	if replyLen != 24 {
		t.Fatalf("replyLen = %d, want 24", replyLen)
	}
	replyType := binary.LittleEndian.Uint32(reply[0:4])
	if replyType != MsgResumeProcess {
		t.Errorf("reply type = %d, want MsgResumeProcess (%d)", replyType, MsgResumeProcess)
	}
	replyReqId := binary.LittleEndian.Uint64(reply[8:16])
	if replyReqId != 42 {
		t.Errorf("reply requestId = %d, want 42", replyReqId)
	}
	replyDecision := binary.LittleEndian.Uint32(reply[16:20])
	if replyDecision != uint32(ExecDecisionResume) {
		t.Errorf("reply decision = %d, want %d (Resume)", replyDecision, ExecDecisionResume)
	}
}

// TestExecPipeline_TerminateReply verifies that a terminate decision produces
// a MsgTerminateProcess reply.
func TestExecPipeline_TerminateReply(t *testing.T) {
	dc := NewDriverClient()
	dc.SetSuspendedProcessHandler(func(req *SuspendedProcessRequest) ExecDecision {
		return ExecDecisionTerminate
	})

	// Build minimal MsgProcessSuspended message
	const maxPath = 520
	const maxCmdLine = 2048
	msgSize := 16 + 8 + 4 + 4 + 8 + 8 + (maxPath * 2) + (maxCmdLine * 2)
	msg := make([]byte, msgSize)
	binary.LittleEndian.PutUint32(msg[0:4], MsgProcessSuspended)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 99) // requestId

	reply := make([]byte, 24)
	replyLen := dc.handleSuspendedProcess(msg, reply)

	if replyLen != 24 {
		t.Fatalf("replyLen = %d, want 24", replyLen)
	}
	replyType := binary.LittleEndian.Uint32(reply[0:4])
	if replyType != MsgTerminateProcess {
		t.Errorf("reply type = %d, want MsgTerminateProcess (%d)", replyType, MsgTerminateProcess)
	}
	replyDecision := binary.LittleEndian.Uint32(reply[16:20])
	if replyDecision != uint32(ExecDecisionTerminate) {
		t.Errorf("reply decision = %d, want %d (Terminate)", replyDecision, ExecDecisionTerminate)
	}
}

// TestCommandLineParsing tests SplitCommandLine with various Windows command line formats.
func TestCommandLineParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "quoted path with flags",
			input:    `"C:\Program Files\Git\bin\git.exe" commit -m "initial commit"`,
			expected: []string{`C:\Program Files\Git\bin\git.exe`, "commit", "-m", "initial commit"},
		},
		{
			name:     "simple exe",
			input:    `cmd.exe /c dir`,
			expected: []string{"cmd.exe", "/c", "dir"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "single arg",
			input:    `notepad.exe`,
			expected: []string{"notepad.exe"},
		},
		{
			name:     "multiple spaces between args",
			input:    `foo.exe   bar   baz`,
			expected: []string{"foo.exe", "bar", "baz"},
		},
		{
			name:     "consecutive quoted args",
			input:    `"a b" "c d"`,
			expected: []string{"a b", "c d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitCommandLine(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("len = %d (%v), want %d (%v)", len(result), result, len(tt.expected), tt.expected)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("[%d] = %q, want %q", i, result[i], tt.expected[i])
				}
			}
		})
	}
}
