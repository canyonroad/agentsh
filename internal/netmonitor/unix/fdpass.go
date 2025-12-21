//go:build linux

package unix

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RecvFD receives one fd over a Unix domain socket (SCM_RIGHTS).
func RecvFD(sock *os.File) (*os.File, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 || oobn == 0 {
		return nil, fmt.Errorf("no fd received")
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return os.NewFile(uintptr(fds[0]), "notif-fd"), nil
		}
	}
	return nil, fmt.Errorf("no fd in control message")
}

// SendFD sends fd over sock.
func SendFD(sock *os.File, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(int(sock.Fd()), []byte{0}, rights, nil, 0)
}
