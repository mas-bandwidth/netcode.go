//go:build !windows

package netcode

import (
	"errors"
	"syscall"
)

// isBindError reports whether a socket create error is a bind failure (the
// port is already in use or not permitted), as opposed to any other socket
// error.
func isBindError(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EACCES)
}
