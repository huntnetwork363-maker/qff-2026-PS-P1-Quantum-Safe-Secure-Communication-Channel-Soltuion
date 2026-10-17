# Threat model

## Assets
Confidentiality and integrity of application data; authenticity of the server; secrecy of session keys.

## Attacker capabilities
| Attacker | Capability | Covered by |
|---|---|---|
| Passive eavesdropper | Records all traffic (incl. for later decryption) | Hybrid KEM: key stays secret unless BOTH ECDH-P256 and ML-KEM-768 are broken |
| Active network attacker (MITM) | Modify/inject/drop/replay messages | ML-DSA-65 signature over the full transcript + Finished MACs + AEAD with sequence numbers |
| Downgrade attacker | Swap suites to a weaker one | suite id inside transcript + explicit client suite check |
| Future quantum attacker | Breaks ECDH/ECDSA retroactively on recorded traffic | ML-KEM-768 share protects recorded sessions |

## Harvest-now, decrypt-later (HNDL)
An adversary can record today's traffic and decrypt it once a quantum computer exists. A classical-only ECDH channel is
exposed to this. The hybrid combiner derives keys from `ss_ecdh || ss_mlkem` through HKDF, so recordings stay safe if
EITHER component holds: it hedges a quantum break of ECDH AND an undiscovered flaw in ML-KEM (a young algorithm).

## What this design does NOT protect against
- **Endpoint compromise** (malware, memory disclosure).
- **Side channels:** kyber-py and dilithium-py are pure-Python research code, not constant-time, not production-grade.
- **Server long-term key compromise:** the ML-DSA key authenticates but the session KEMs are ephemeral, so past sessions
  stay confidential, but an attacker holding the signing key can impersonate the server from then on.
- **No PKI / revocation / certificates:** the server public key is pinned by the client out of band (trust anchor assumption).
- **Client authentication:** only the server is authenticated.
- **Traffic analysis / metadata,** denial of service, network latency/loss (in-memory transport only).
- **Quantum attack on the signature before key compromise:** the classical-baseline suite uses ECDSA, which is NOT quantum-safe;
  it exists only as a benchmark baseline.

## Assumptions
Pinned server public key is authentic; OS randomness is sound; the libraries (`cryptography`, `kyber-py`, `dilithium-py`)
implement their standards correctly (ML-KEM cross-checked against a second implementation, see BUGLOG).

## Negative control
`mitm_unsigned_control` shows that WITHOUT authentication a full MITM succeeds against any KEM-based channel, which is
why the signature is mandatory in the real protocol (the unsigned mode exists only for this demonstration).
