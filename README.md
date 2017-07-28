![](https://github.com/tvdmerwe/spearmint/blob/dev/mint.svg)

spearmint - A Minimal TLS 1.3 Reverse Firewall Implementation
==============================

This project serves as a Proof-of-Concept (PoC) for the TLS 1.3 cryptographic reverse
firewall construction presented in [Reverse Firewalls for Secure-Channel Establishment
Revisited: Towards reverse firewalls for TLS 1.3](). The project builds
on top of the [mint TLS 1.3 implementation](https://github.com/bifurcation/mint) which
in turn borrows liberally from the [Go TLS
library](https://golang.org/pkg/crypto/tls/), especially where TLS 1.3 aligns
with earlier TLS versions.

In order to successfully implement a reverse firewall for TLS 1.3, several modifications
to the protocol need to be effected. We briefly note these modifications here and
refer readers to the academic paper for further details:

1. **Nonces.** In order to avoid exfiltration of data via the client and server
nonces, these values are set to 0.

2. **Pairing-friendly curves.** The construction relies on an intelligent use of
bilinear pairings. As TLS 1.3 currently does not support pairing-friendly curves
(and associated groups) we modify the Mint implementation to enable use of
Barreto-Naehrig curves at the 128-bit security level. We make use of [bn256](https://godoc.org/golang.org/x/crypto/bn256) Go
package.

3. **Session hash.** We adapt the session hash to account for the malleability
introduced by the firewall.

4. **Key schedule separation.** In order to allow for the firewall to effectively
provide protection from exfiltration of data without knowing the application data
traffic keys shared between a client and a server, we spilt or "spear" the TLS 1.3 key
schedule into two distinct trees.

5. **Double encryption.** We implement double encryption at the record layer to
prevent exfiltration of sensitive data over the secure channel.  

## Performance

TODO: Add text here when complete.

## Quickstart

Installation is identical to any other Go package:

```
go get github.com/tvdmerwe/spearmint
```
TODO: Make active when ready.

Documentation is available on ...

TODO: Add this if necessary.
<! -- [godoc.org](https://godoc.org/github.com/bifurcation/mint) -->

## Testing

The `mint-client`, `mint-server` and `mint-firewall` executables are included
to make it easy to confirm operation. The steps
for testing are as follows:

```
# Install spearmint
go get github.com/tvdmerwe/spearmint

# Test with client=spearmint firewall=spearmint server=spearmint
# Open a terminal window for the firewall
go run $GOPATH/src/github.com/tvdmerwe/spearmint/bin/mint-firewall/main.go
# Open a terminal window for the server
go run $GOPATH/src/github.com/tvdmerwe/spearmint/bin/mint-server/main.go
# Open a terminal window for the client
go run $GOPATH/src/github.com/tvdmerwe/spearmint/bin/mint-client/main.go

```
