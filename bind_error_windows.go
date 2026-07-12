//go:build windows

package netcode

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isBindError reports whether a socket create error is a bind failure (the
// port is already in use or not permitted), as opposed to any other socket
// error. Winsock reports these as WSA error codes, which do not match the
// portable syscall errno constants.
func isBindError(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}
