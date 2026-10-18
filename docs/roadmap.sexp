; netcode.go roadmap: the data ROADMAP.md is generated from (nova-tools tools/roadmap;
; make roadmap renders, make roadmap-check fails on drift). Read as data, never evaluated.
; A cell is done only when its task is :done with :evidence, a test or a commit;
; :tested-revision is the main commit whose CI passed with that evidence.
(:schema 1
 :root "goal"
 :page (:title "netcode.go roadmap"
        :roadmaps ("connection" "security" "network" "compat" "testing"))
 :nodes
 ((:id "goal" :type :work-set :children ("connection" "security" "network" "compat" "testing"))
  (:id "connection" :type :roadmap :title "Connection"
   :text "Connect tokens, client slots, the handshake, keep-alive, disconnects and timeouts between a client and a server."
   :rows (("connect-tokens" "connect tokens issued by a web backend")
          ("handshake" "request, challenge and response handshake")
          ("slots" "client slots; a full server denies at once")
          ("many-clients" "many clients on one server")
          ("server-list" "fall through to the next server in the token")
          ("keep-alive" "keep-alive")
          ("disconnect-client" "clean disconnect from the client")
          ("disconnect-server" "clean disconnect from the server, with a reason")
          ("timeouts" "request, response and connection timeouts")
          ("bad-tokens" "expired and invalid connect tokens refused")
          ("reconnect" "reconnect with a new token")
          ("no-timeout" "timeouts can be disabled for debugging")
          ("loopback" "loopback clients inside the server process")
          ("loopback-callback" "loopback refuses to connect without its send callback")
          ("disconnect-callback" "the disconnect callback cannot re-enter a slot being cleared")
          ("socketless-address" "the client skips a server address it has no socket for"))
   :columns (("done" "done"))
   :cells (("connect-tokens" "done" "connection/connect-tokens")
           ("handshake" "done" "connection/handshake")
           ("slots" "done" "connection/slots")
           ("many-clients" "done" "connection/many-clients")
           ("server-list" "done" "connection/server-list")
           ("keep-alive" "done" "connection/keep-alive")
           ("disconnect-client" "done" "connection/disconnect-client")
           ("disconnect-server" "done" "connection/disconnect-server")
           ("timeouts" "done" "connection/timeouts")
           ("bad-tokens" "done" "connection/bad-tokens")
           ("reconnect" "done" "connection/reconnect")
           ("no-timeout" "done" "connection/no-timeout")
           ("loopback" "done" "connection/loopback")
           ("loopback-callback" "done" "connection/loopback-callback")
           ("disconnect-callback" "done" "connection/disconnect-callback")
           ("socketless-address" "done" "connection/socketless-address")))
  (:id "connection/connect-tokens" :type :task :title "connect tokens issued by a web backend" :state :done :evidence ("netcode_test.go: TestConnectToken" "netcode_test.go: TestConnectTokenPublic" "example_test.go: ExampleGenerateConnectToken") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/handshake" :type :task :title "request, challenge and response handshake" :state :done :evidence ("client_server_test.go: TestClientServerConnect" "netcode_test.go: TestChallengeToken") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/slots" :type :task :title "client slots; a full server denies at once" :state :done :evidence ("client_server_test.go: TestClientErrorConnectionDenied") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/many-clients" :type :task :title "many clients on one server" :state :done :evidence ("client_server_test.go: TestClientServerMultipleClients") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/server-list" :type :task :title "fall through to the next server in the token" :state :done :evidence ("client_server_test.go: TestClientServerMultipleServers") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/keep-alive" :type :task :title "keep-alive" :state :done :evidence ("client_server_test.go: TestClientServerKeepAlive") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/disconnect-client" :type :task :title "clean disconnect from the client" :state :done :evidence ("client_server_test.go: TestClientSideDisconnect") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/disconnect-server" :type :task :title "clean disconnect from the server, with a reason" :state :done :evidence ("client_server_test.go: TestServerSideDisconnect" "client_server_test.go: TestServerClientDisconnectReason") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/timeouts" :type :task :title "request, response and connection timeouts" :state :done :evidence ("client_server_test.go: TestClientErrorConnectionRequestTimeout" "client_server_test.go: TestClientErrorConnectionResponseTimeout" "client_server_test.go: TestClientErrorConnectionTimedOut") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/bad-tokens" :type :task :title "expired and invalid connect tokens refused" :state :done :evidence ("client_server_test.go: TestClientErrorConnectTokenExpired" "client_server_test.go: TestClientErrorInvalidConnectToken") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/reconnect" :type :task :title "reconnect with a new token" :state :done :evidence ("client_server_test.go: TestClientReconnect") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/no-timeout" :type :task :title "timeouts can be disabled for debugging" :state :done :evidence ("client_server_test.go: TestDisableTimeout") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/loopback" :type :task :title "loopback clients inside the server process" :state :done :evidence ("client_server_test.go: TestLoopback") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "connection/loopback-callback" :type :task :title "loopback refuses to connect without its send callback" :state :todo
   :note "Refuse both connects, in every build, when the send-loopback callback is nil, with a log line naming why; no wire change."
   :sprint-card "go-netcode-loopback-callback-is-required")
  (:id "connection/disconnect-callback" :type :task :title "the disconnect callback cannot re-enter a slot being cleared" :state :todo
   :note "disconnectClientInternal (server.go) calls ConnectDisconnectCallback before the encryption mapping and the slot are cleared."
   :sprint-card "go-netcode-disconnect-callback-cannot-reenter-a-clearing-slot")
  (:id "connection/socketless-address" :type :task :title "the client skips a server address it has no socket for" :state :todo
   :note "Connect and connectToNextServer should skip an address whose family has no socket (simulator and override modes exempt), and set ClientStateInvalidConnectToken if none is usable."
   :sprint-card "go-netcode-client-refuses-a-server-address-it-has-no-socket-for")
  (:id "security" :type :roadmap :title "Security"
   :text "Encrypted, signed packets and the protections against forged, replayed and malformed traffic."
   :rows (("aead" "encrypted and signed packets (ChaCha20-Poly1305)")
          ("private-token" "encrypted connect token private data (XChaCha20-Poly1305)")
          ("replay" "replay protection")
          ("token-reuse" "a used connect token is refused")
          ("token-history" "a full token history refuses rather than forgets")
          ("token-predates" "a token created before the server started is refused")
          ("restart-nonce" "no nonce reuse across a server restart")
          ("malformed" "malformed packets and tokens refused, fuzzed")
          ("amplification" "amplification protection")
          ("own-challenge" "each connection response is bound to its own challenge")
          ("replay-top" "replay protection at the top of the sequence space")
          ("mapping-lifetime" "pre-connect mappings expire even for tokens without a timeout")
          ("shared-token-nonces" "servers sharing a connect token use distinct global packet nonces"))
   :columns (("done" "done"))
   :cells (("aead" "done" "security/aead")
           ("private-token" "done" "security/private-token")
           ("replay" "done" "security/replay")
           ("token-reuse" "done" "security/token-reuse")
           ("token-history" "done" "security/token-history")
           ("token-predates" "done" "security/token-predates")
           ("restart-nonce" "done" "security/restart-nonce")
           ("malformed" "done" "security/malformed")
           ("amplification" "done" "security/amplification")
           ("own-challenge" "done" "security/own-challenge")
           ("replay-top" "done" "security/replay-top")
           ("mapping-lifetime" "done" "security/mapping-lifetime")
           ("shared-token-nonces" "done" "security/shared-token-nonces")))
  (:id "security/aead" :type :task :title "encrypted and signed packets (ChaCha20-Poly1305)" :state :done :evidence ("netcode_test.go: TestConnectionPayloadPacket" "netcode_test.go: TestEncryptionManager") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/private-token" :type :task :title "encrypted connect token private data (XChaCha20-Poly1305)" :state :done :evidence ("netcode_test.go: TestConnectToken" "wire_compat_test.go: TestWireCompatConnectTokenPrivate") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/replay" :type :task :title "replay protection" :state :done :evidence ("netcode_test.go: TestReplayProtection") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/token-reuse" :type :task :title "a used connect token is refused" :state :done :evidence ("token_reuse_test.go: TestClientReconnectWithUsedConnectToken" "token_entries_test.go: TestConnectTokenEntries") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/token-history" :type :task :title "a full token history refuses rather than forgets" :state :done :evidence ("token_reuse_test.go: TestConnectTokenHistoryFullServerRefusal" "token_entries_test.go: TestConnectTokenEntriesConsumeBounds") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/token-predates" :type :task :title "a token created before the server started is refused" :state :done :evidence ("token_reuse_test.go: TestClientConnectTokenPredatesServerStart") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/restart-nonce" :type :task :title "no nonce reuse across a server restart" :state :done :evidence ("restart_test.go: TestServerRestartGlobalSequence") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/malformed" :type :task :title "malformed packets and tokens refused, fuzzed" :state :done :evidence ("fuzz_test.go: FuzzReadPacket" "fuzz_test.go: FuzzReadConnectToken" "fuzz_test.go: FuzzReadConnectTokenPrivate" "fuzz_test.go: FuzzParseAddress") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "security/amplification" :type :task :title "amplification protection" :state :unknown
   :note "The connection request is larger than the challenge it draws (netcode 1.02), but no test here asserts that sizing; a test that a short request is dropped and that the challenge is smaller than the request makes this done.")
  (:id "security/own-challenge" :type :task :title "each connection response is bound to its own challenge" :state :todo
   :note "A response encrypted under token B could carry token A's challenge and connect as A. The server authenticates each challenge with its token's private-data MAC."
   :github-pr "31"
   :pushed-head "b8e0d18a76519cd5e1e8ec4f9126b8de39ab4710"
   :sprint-card "go-netcode-connection-response-takes-only-its-own-mappings-challenge")
  (:id "security/replay-top" :type :task :title "replay protection at the top of the sequence space" :state :todo
   :note "alreadyReceived should return true early when sequence == 0xFFFFFFFFFFFFFFFF."
   :sprint-card "go-netcode-replay-top-sequence-and-restart-floor-edges")
  (:id "security/mapping-lifetime" :type :task :title "pre-connect mappings expire even for tokens without a timeout" :state :todo
   :note "Use server.time + (timeoutSeconds > 0 ? timeoutSeconds : preconnectMappingSeconds) for a pre-connect mapping, with preconnectMappingSeconds = 10."
   :sprint-card "go-netcode-token-lifetimes-are-bounded")
  (:id "security/shared-token-nonces" :type :task :title "servers sharing a connect token use distinct global packet nonces" :state :todo
   :note "Two servers in one token must not encrypt global packets under the same key and nonce."
   :sprint-card "go-netcode-global-packet-nonces-differ-between-servers-sharing-a-token")
  (:id "network" :type :roadmap :title "Networking"
   :text "Sockets, address families, platforms and the tools for testing under bad networks."
   :rows (("ipv4" "IPv4")
          ("ipv6" "IPv6")
          ("dual-stack" "dual-stack server (IPv4 and IPv6 at once)")
          ("tagging" "packet tagging (DSCP) to cut Wi-Fi jitter")
          ("simulator" "network simulator: latency, jitter, loss, duplicates")
          ("platforms" "Linux, macOS and Windows"))
   :columns (("done" "done"))
   :cells (("ipv4" "done" "network/ipv4")
           ("ipv6" "done" "network/ipv6")
           ("dual-stack" "done" "network/dual-stack")
           ("tagging" "done" "network/tagging")
           ("simulator" "done" "network/simulator")
           ("platforms" "done" "network/platforms")))
  (:id "network/ipv4" :type :task :title "IPv4" :state :done :evidence ("client_server_test.go: TestClientServerIPv4SocketConnect") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "network/ipv6" :type :task :title "IPv6" :state :done :evidence ("client_server_test.go: TestClientServerIPv6SocketConnect") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "network/dual-stack" :type :task :title "dual-stack server (IPv4 and IPv6 at once)" :state :done :evidence ("client_server_test.go: TestClientServerDualSocketConnect") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "network/tagging" :type :task :title "packet tagging (DSCP) to cut Wi-Fi jitter" :state :done :evidence ("client_server_test.go: TestPacketTagging") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "network/simulator" :type :task :title "network simulator: latency, jitter, loss, duplicates" :state :done :evidence ("netcode_test.go: TestNetworkSimulatorDeterminism") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "network/platforms" :type :task :title "Linux, macOS and Windows" :state :done :evidence (".github/workflows/ci.yml: test job, matrix ubuntu-latest, macos-latest, windows-latest, green on b709cb1") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "compat" :type :roadmap :title "Compatibility"
   :text "Wire compatibility with the C reference implementation and the netcode 1.02 standard."
   :rows (("standard" "netcode 1.02 standard, kept in sync with upstream")
          ("golden-vectors" "every token and packet type byte-identical to C (golden vectors)")
          ("c-interop" "live handshakes with the C client and server, both directions")
          ("version" "version tracks the C reference (1.4.8)")
          ("c-api" "API maps one to one onto the C API"))
   :columns (("done" "done"))
   :cells (("standard" "done" "compat/standard")
           ("golden-vectors" "done" "compat/golden-vectors")
           ("c-interop" "done" "compat/c-interop")
           ("version" "done" "compat/version")
           ("c-api" "done" "compat/c-api")))
  (:id "compat/standard" :type :task :title "netcode 1.02 standard, kept in sync with upstream" :state :done :evidence (".github/workflows/ci.yml: spec-sync job (STANDARD.md matches upstream)" "commit 457475a (vendor STANDARD.md, with a drift check)") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "compat/golden-vectors" :type :task :title "every token and packet type byte-identical to C (golden vectors)" :state :done :evidence ("wire_compat_test.go: TestWireCompatConnectToken" "wire_compat_test.go: TestWireCompatChallengeToken" "wire_compat_test.go: TestWireCompatConnectionRequestPacket" "wire_compat_test.go: TestWireCompatConnectionResponsePacket" "wire_compat_test.go: TestWireCompatConnectionPayloadPacket") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "compat/c-interop" :type :task :title "live handshakes with the C client and server, both directions" :state :done :evidence ("c_interop_test.go: TestCInteropClientConnectsToCServer" "c_interop_test.go: TestCInteropCClientConnectsToGoServer" ".github/workflows/ci.yml: wire-compat job") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "compat/version" :type :task :title "version tracks the C reference (1.4.8)" :state :done :evidence ("commit 7d4daec (C 1.4.8 lifecycle, #29)" ".github/workflows/ci.yml: version-sync job") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "compat/c-api" :type :task :title "API maps one to one onto the C API" :state :done :evidence ("example_test.go: ExampleNewServer" "example_test.go: ExampleNewClient") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "testing" :type :roadmap :title "Testing"
   :text "How the implementation is checked on every change."
   :rows (("race" "race detector on every change")
          ("fuzz" "fuzz targets ported from the C harnesses")
          ("soak" "soak test")
          ("vulncheck" "lint and vulnerability scan"))
   :columns (("done" "done"))
   :cells (("race" "done" "testing/race")
           ("fuzz" "done" "testing/fuzz")
           ("soak" "done" "testing/soak")
           ("vulncheck" "done" "testing/vulncheck")))
  (:id "testing/race" :type :task :title "race detector on every change" :state :done :evidence (".github/workflows/ci.yml: test job, Test (race)") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "testing/fuzz" :type :task :title "fuzz targets ported from the C harnesses" :state :done :evidence ("fuzz_test.go: FuzzReadPacket" "fuzz_test.go: FuzzWriteReadPacketRoundTrip" "fuzz_test.go: FuzzConnectTokenPrivateRoundTrip" ".github/workflows/ci.yml: smoke job") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "testing/soak" :type :task :title "soak test" :state :done :evidence ("cmd/soak: go run ./cmd/soak 500 in the ci.yml smoke job") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")
  (:id "testing/vulncheck" :type :task :title "lint and vulnerability scan" :state :done :evidence (".github/workflows/ci.yml: lint and vulncheck jobs") :tested-revision "b709cb150b7c562828d3d9a7f237361681efaf3f")))
