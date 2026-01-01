// internal/platform/windows/fltlib_windows.go
//go:build windows

package windows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modFltLib = windows.NewLazySystemDLL("fltlib.dll")

	procFilterConnectCommunicationPort = modFltLib.NewProc("FilterConnectCommunicationPort")
	procFilterSendMessage              = modFltLib.NewProc("FilterSendMessage")
	procFilterGetMessage               = modFltLib.NewProc("FilterGetMessage")
	procFilterReplyMessage             = modFltLib.NewProc("FilterReplyMessage")
)

// filterConnectCommunicationPort connects to a mini-filter communication port
func filterConnectCommunicationPort(
	portName *uint16,
	options uint32,
	context unsafe.Pointer,
	sizeOfContext uint16,
	securityAttributes *windows.SecurityAttributes,
	port *windows.Handle,
) error {
	r1, _, e1 := syscall.SyscallN(
		procFilterConnectCommunicationPort.Addr(),
		uintptr(unsafe.Pointer(portName)),
		uintptr(options),
		uintptr(context),
		uintptr(sizeOfContext),
		uintptr(unsafe.Pointer(securityAttributes)),
		uintptr(unsafe.Pointer(port)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// filterSendMessage sends a message to the mini-filter driver
func filterSendMessage(
	port windows.Handle,
	inBuffer []byte,
	outBuffer []byte,
) error {
	var outBufPtr unsafe.Pointer
	var outBufSize uint32
	var bytesReturned uint32

	if len(outBuffer) > 0 {
		outBufPtr = unsafe.Pointer(&outBuffer[0])
		outBufSize = uint32(len(outBuffer))
	}

	r1, _, e1 := syscall.SyscallN(
		procFilterSendMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&inBuffer[0])),
		uintptr(len(inBuffer)),
		uintptr(outBufPtr),
		uintptr(outBufSize),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// FILTER_MESSAGE_HEADER is the header for messages from the driver
type FILTER_MESSAGE_HEADER struct {
	ReplyLength uint32
	MessageId   uint64
}

// filterGetMessage receives a message from the mini-filter driver
func filterGetMessage(
	port windows.Handle,
	messageBuffer []byte,
	messageBufferSize uint32,
	bytesReturned *uint32,
) error {
	// FltLib expects a FILTER_MESSAGE_HEADER at the start
	r1, _, e1 := syscall.SyscallN(
		procFilterGetMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&messageBuffer[0])),
		uintptr(messageBufferSize),
		0, // Overlapped (NULL for synchronous)
	)
	if r1 != 0 {
		return e1
	}
	return nil
}

// filterReplyMessage sends a reply to the mini-filter driver
func filterReplyMessage(
	port windows.Handle,
	replyBuffer []byte,
) error {
	r1, _, e1 := syscall.SyscallN(
		procFilterReplyMessage.Addr(),
		uintptr(port),
		uintptr(unsafe.Pointer(&replyBuffer[0])),
		uintptr(len(replyBuffer)),
	)
	if r1 != 0 {
		return e1
	}
	return nil
}
