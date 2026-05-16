//go:build linux

package wraphandoff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	protocolMagic byte = 0xA7
	StatusReject  byte = 0
	StatusOK      byte = 1
)

type Metadata struct {
	WrapperPID int
}

func SendNotifyFD(conn *net.UnixConn, notifyFD int, meta Metadata) error {
	if conn == nil {
		return errors.New("nil unix connection")
	}
	if notifyFD < 0 {
		return fmt.Errorf("invalid notify fd %d", notifyFD)
	}

	payload := make([]byte, 5)
	payload[0] = protocolMagic
	binary.LittleEndian.PutUint32(payload[1:], uint32(meta.WrapperPID))
	rights := unix.UnixRights(notifyFD)
	n, oobn, err := conn.WriteMsgUnix(payload, rights, nil)
	if err != nil {
		return fmt.Errorf("send notify fd: %w", err)
	}
	if n != len(payload) || oobn != len(rights) {
		return fmt.Errorf("send notify fd: %w (n=%d/%d, oobn=%d/%d)", io.ErrShortWrite, n, len(payload), oobn, len(rights))
	}
	return nil
}

func RecvNotifyFD(conn *net.UnixConn) (*os.File, Metadata, bool, error) {
	if conn == nil {
		return nil, Metadata{}, false, errors.New("nil unix connection")
	}

	buf := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4*8))
	n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, Metadata{}, false, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 || oobn == 0 {
		return nil, Metadata{}, false, fmt.Errorf("no fd received (n=%d, oobn=%d)", n, oobn)
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		if flags&unix.MSG_CTRUNC != 0 {
			return nil, Metadata{}, false, fmt.Errorf("truncated control message: %w", err)
		}
		return nil, Metadata{}, false, fmt.Errorf("parse control message: %w", err)
	}

	var receivedFDs []int
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		receivedFDs = append(receivedFDs, fds...)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		closeFDs(receivedFDs)
		return nil, Metadata{}, false, errors.New("truncated control message")
	}
	if len(receivedFDs) != 1 {
		closeFDs(receivedFDs)
		return nil, Metadata{}, false, fmt.Errorf("expected exactly one fd, received %d", len(receivedFDs))
	}

	fd := receivedFDs[0]
	unix.CloseOnExec(fd)
	meta := Metadata{}
	hasMeta := n >= 5 && buf[0] == protocolMagic
	if hasMeta {
		meta.WrapperPID = int(binary.LittleEndian.Uint32(buf[1:5]))
	}
	return os.NewFile(uintptr(fd), "wrap-notif-fd"), meta, hasMeta, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func WriteStatus(w io.Writer, ok bool) error {
	if w == nil {
		return errors.New("nil writer")
	}

	b := StatusReject
	if ok {
		b = StatusOK
	}
	n, err := w.Write([]byte{b})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func ReadStatus(r io.Reader) error {
	if r == nil {
		return errors.New("nil reader")
	}

	buf := []byte{0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read setup status: %w", err)
	}
	switch buf[0] {
	case StatusOK:
		return nil
	case StatusReject:
		return errors.New("server rejected wrap setup")
	default:
		return fmt.Errorf("unexpected setup status byte %d", buf[0])
	}
}
