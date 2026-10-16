; The netcode.go roadmap: the data ROADMAP.md is generated from.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment):
; data, never evaluated. Edit this file, then regenerate ROADMAP.md with nova-sprint's
; generator, from a nova-sprint checkout:
;   go build -o /tmp/roadmap ./tools/roadmap && (cd <this repo> && /tmp/roadmap --file docs/roadmap.sexp --out ROADMAP.md)
; Never edit ROADMAP.md by hand. Created 2026-10-14 when the open sprint cards of this
; repository were moved out of the stopped sprint.
(roadmap "v1"
 :title "netcode.go roadmap"
 :text "Planned work for netcode.go. Each item below was an open sprint card, moved out of the stopped sprint on 2026-10-14; it names its card, its tier, its base branch and any pushed work to resume from. Landed work is in git."

 :groups
 (
  (group "github-issues" :title "Moved from GitHub issues on 2026-10-14"
   :text "Open GitHub issues of mas-bandwidth/netcode.go, recorded here on 2026-10-14 when roadmaps became the standard for future work (Glenn, 2026-10-14). Each item names its issue; the issue is closed with a pointer here.")

  (group "export-netcode-go-port" :title "Moved out of the sprint on 2026-10-14: netcode-go-port"
   :text "The open cards of sprint stream netcode-go-port, moved out of the stopped sprint on 2026-10-14, one item per card. Landed cards of the stream are in git and are not listed. Each item names its card, its tier, its base branch and any pushed work to resume from.")
 )

 :items
 (
  (item "issue-22" :group "github-issues" :area "netcode.go"
   :title "VersionFull pins 1.4.3; upstream netcode is now 1.4.4"
   :text "netcode.go pins VersionFull at 1.4.3 and CI carries a check named VersionFull matches upstream. Upstream netcode cut v1.4.4 today (strict floating-point builds, no wire change), so that check will demand the follow-up on its next run against the new upstream release."
   :date "2026-10-14"
   :origin "mas-bandwidth/netcode.go issue #22, opened 2026-08-26 by rowan-claude; moved here 2026-10-14"
   :kept (:github-issue "22" :labels ""))

  (item "go-netcode-connection-response-takes-only-its-own-mappings-challenge" :group "export-netcode-go-port" :area "netcode.go"
   :title "Bind connection responses to their own mapping challenge"
   :text "Bind connection challenges to the connect token that created the server's encryption mapping. Previously, a response encrypted under token B's packet key could carry token A's challenge and connect as A with A's user data. The server now authenticates each challenge with that token's private-data MAC and refuses a response when its mapping has no token entry."
   :exists "Work was pushed: head b8e0d18a76519cd5e1e8ec4f9126b8de39ab4710 on branch sprint/go-netcode-connection-response-takes-only-its-own-mappings-challenge.w1.g1.e20, open as draft pull request #31. Resume from it; do not start over."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "mas-bandwidth/netcode.go pull request #31 (draft), opened 2026-10-14 by gafferongames, for sprint card go-netcode-connection-response-takes-only-its-own-mappings-challenge (stream netcode-go-port, base sprint/netcode-go-port); added here 2026-10-16"
   :kept (:github-pr "31" :labels "" :sprint-card "go-netcode-connection-response-takes-only-its-own-mappings-challenge" :sprint-stream "netcode-go-port" :sprint-base "sprint/netcode-go-port" :pushed-head "b8e0d18a76519cd5e1e8ec4f9126b8de39ab4710" :pushed-branch "sprint/go-netcode-connection-response-takes-only-its-own-mappings-challenge.w1.g1.e20"))
  (item "go-netcode-disconnect-callback-cannot-reenter-a-clearing-slot" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode disconnect callback cannot reenter a clearing slot"
   :text "disconnectClientInternal (server.go:353-380) calls ConnectDisconnectCallback at 360-362 before `server.encryptionManager.clientIndex[server.clientEncryptionIndex[clientIndex]] = -1` (375) and resetClientSlot (379)."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-disconnect-callback-cannot-reenter-a-clearing-slot (stream netcode-go-port, column working, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-disconnect-callback-cannot-reenter-a-clearing-slot" :sprint-stream "netcode-go-port" :sprint-column "working" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-connection-response-takes-only-its-own-mappings-challenge" :pushed-head "" :pushed-branch ""))
  (item "go-netcode-replay-top-sequence-and-restart-floor-edges" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode replay top sequence and restart floor edges"
   :text "N4: return true early from alreadyReceived when sequence == 0xFFFFFFFFFFFFFFFF, with a one-line comment."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-replay-top-sequence-and-restart-floor-edges (stream netcode-go-port, column waiting, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-replay-top-sequence-and-restart-floor-edges" :sprint-stream "netcode-go-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-disconnect-callback-cannot-reenter-a-clearing-slot,netfix-restart-floor-refuses-a-token-from-the-start-second" :pushed-head "" :pushed-branch ""))
  (item "go-netcode-token-lifetimes-are-bounded" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode token lifetimes are bounded"
   :text "N7: add `preconnectMappingSeconds = 10` in netcode.go and use `server.time + (timeoutSeconds > 0 ? timeoutSeconds : preconnectMappingSeconds)` for a pre-connect mapping (promotion already clears the expiry)."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-token-lifetimes-are-bounded (stream netcode-go-port, column waiting, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-token-lifetimes-are-bounded" :sprint-stream "netcode-go-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-replay-top-sequence-and-restart-floor-edges,netfix-preconnect-mapping-lifetime-ignores-a-nonpositive-token-timeout,netfix-never-expiring-tokens-are-refused-or-documented-against-the-restart-floor" :pushed-head "" :pushed-branch ""))
  (item "go-netcode-client-refuses-a-server-address-it-has-no-socket-for" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode client refuses a server address it has no socket for"
   :text "Memory-safe: Client.receivePackets breaks on a nil socket (client.go:379-381) and the send is dropped (socket.go:198-201). A clientHasSocketFor(addr) helper that exempts the simulator and override modes (they have no sockets by design); Connect and connectToNextServer skip an address whose family has no socket, and set ClientStateInvalidConnectToken if none is usable."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-client-refuses-a-server-address-it-has-no-socket-for (stream netcode-go-port, column waiting, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-client-refuses-a-server-address-it-has-no-socket-for" :sprint-stream "netcode-go-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-token-lifetimes-are-bounded,netfix-client-refuses-a-server-address-it-has-no-socket-for" :pushed-head "" :pushed-branch ""))
  (item "go-netcode-global-packet-nonces-differ-between-servers-sharing-a-token" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode global packet nonces differ between servers sharing a token"
   :text "Go netcode global packet nonces differ between servers sharing a token. Done when: the new tests are red before the fix and green after it;"
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-global-packet-nonces-differ-between-servers-sharing-a-token (stream netcode-go-port, column waiting, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-global-packet-nonces-differ-between-servers-sharing-a-token" :sprint-stream "netcode-go-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-client-refuses-a-server-address-it-has-no-socket-for,netfix-global-packet-nonces-differ-between-servers-sharing-a-token" :pushed-head "" :pushed-branch ""))
  (item "go-netcode-loopback-callback-is-required" :group "export-netcode-go-port" :area "netcode.go"
   :title "Go netcode loopback callback is required"
   :text "Refuse both connects, in every build, when the send-loopback callback is nil, with a log line naming why; no wire change."
   :why "Moved out of the stopped sprint on 2026-10-14: neither rocketnet nor v1.3 work."
   :date "2026-10-14"
   :origin "sprint card go-netcode-loopback-callback-is-required (stream netcode-go-port, column waiting, tier pro, base sprint/netcode-go-port), moved out of the sprint 2026-10-14"
   :kept (:sprint-card "go-netcode-loopback-callback-is-required" :sprint-stream "netcode-go-port" :sprint-column "waiting" :tier "pro" :sprint-base "sprint/netcode-go-port" :needs "go-netcode-global-packet-nonces-differ-between-servers-sharing-a-token" :pushed-head "" :pushed-branch ""))
))
