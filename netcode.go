/*
Package netcode implements the netcode 1.02 protocol: a simple protocol
for creating secure client/server connections over UDP.

This is a faithful port of the C reference implementation at
https://github.com/mas-bandwidth/netcode and is wire compatible with it.
See STANDARD.md for the protocol specification.

# Copyright © 2017 - 2026, Más Bandwidth LLC

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package netcode

import "fmt"

// IMPORTANT: netcode is single-threaded by design and is not thread safe.
//
// The package-level state (the log level and printf hook) performs no internal
// synchronization, and each Client and Server must only be updated from one
// goroutine at a time. Sockets are read by internal goroutines, but all
// protocol logic runs on the goroutine that calls Update.

const (
	VersionFull  = "1.3.5"
	VersionMajor = 1
	VersionMinor = 3
	VersionPatch = 5
)

const (
	ConnectTokenBytes    = 2048
	KeyBytes             = 32
	MacBytes             = 16
	UserDataBytes        = 256
	MaxServersPerConnect = 32

	MaxClients    = 256
	MaxPacketSize = 1200
)

const (
	connectTokenNonceBytes     = 24
	connectTokenPrivateBytes   = 1024
	challengeTokenBytes        = 300
	versionInfoBytes           = 13
	maxPacketBytes             = 1300
	maxPayloadBytes            = 1200
	maxAddressStringLength     = 256
	packetQueueSize            = 256
	replayProtectionBufferSize = 256
)

// versionInfo is written to unencrypted packet headers and mixed into the AEAD
// associated data. "NETCODE 1.02" ASCII with null terminator (13 bytes).
var versionInfo = [versionInfoBytes]byte{'N', 'E', 'T', 'C', 'O', 'D', 'E', ' ', '1', '.', '0', '2', 0}

const (
	packetSendRate       = 10.0
	numDisconnectPackets = 10
)

// Client states. The initial state is ClientStateDisconnected. Negative states
// are error states. The goal state is ClientStateConnected.
const (
	ClientStateConnectTokenExpired        = -6
	ClientStateInvalidConnectToken        = -5
	ClientStateConnectionTimedOut         = -4
	ClientStateConnectionResponseTimedOut = -3
	ClientStateConnectionRequestTimedOut  = -2
	ClientStateConnectionDenied           = -1
	ClientStateDisconnected               = 0
	ClientStateSendingConnectionRequest   = 1
	ClientStateSendingConnectionResponse  = 2
	ClientStateConnected                  = 3
)

// ClientStateName returns a human readable name for a client state.
func ClientStateName(clientState int) string {
	switch clientState {
	case ClientStateConnectTokenExpired:
		return "connect token expired"
	case ClientStateInvalidConnectToken:
		return "invalid connect token"
	case ClientStateConnectionTimedOut:
		return "connection timed out"
	case ClientStateConnectionRequestTimedOut:
		return "connection request timed out"
	case ClientStateConnectionResponseTimedOut:
		return "connection response timed out"
	case ClientStateConnectionDenied:
		return "connection denied"
	case ClientStateDisconnected:
		return "disconnected"
	case ClientStateSendingConnectionRequest:
		return "sending connection request"
	case ClientStateSendingConnectionResponse:
		return "sending connection response"
	case ClientStateConnected:
		return "connected"
	default:
		return "???"
	}
}

// The reason the client in a server slot was last disconnected. Tracked per-client slot:
// reset to None when the server starts and when a new client connects to the slot, and
// recorded before the connect/disconnect callback fires, so it can be queried from inside
// that callback via Server.ClientDisconnectReason.
const (
	DisconnectReasonNone             = 0
	DisconnectReasonTimedOut         = 1
	DisconnectReasonClientDisconnect = 2
	DisconnectReasonServerDisconnect = 3
)

// Log levels.
const (
	LogLevelNone  = 0
	LogLevelError = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
)

var logLevel int

var printfFunction = func(format string, args ...any) {
	fmt.Printf(format, args...)
}

// SetLogLevel sets the log level. The default is LogLevelNone.
func SetLogLevel(level int) {
	logLevel = level
}

// SetPrintfFunction overrides where log output goes. The default prints to stdout.
func SetPrintfFunction(function func(format string, args ...any)) {
	if function == nil {
		panic("netcode: printf function must not be nil")
	}
	printfFunction = function
}

func printf(level int, format string, args ...any) {
	if level > logLevel {
		return
	}
	printfFunction(format, args...)
}
