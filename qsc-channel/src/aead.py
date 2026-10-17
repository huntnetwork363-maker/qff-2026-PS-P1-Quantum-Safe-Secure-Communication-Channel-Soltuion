"""AES-256-GCM record protection with per-direction counter nonces (4-byte fixed prefix || 8-byte big-endian counter).
The nonce is derived from a strictly increasing counter, never random, so it can never repeat for a given key."""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_SEQ = 2**64 - 1


class AEADError(Exception):
    """Authentication failure, replay/reorder, or counter exhaustion."""


class Direction:
    def __init__(self, key, prefix, start_seq=0):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        if len(prefix) != 4:
            raise ValueError("nonce prefix must be 4 bytes")
        self._aes = AESGCM(bytes(key))
        self._prefix = bytes(prefix)
        self.seq = start_seq
        self.last_nonce = None

    def _nonce(self):
        if self.seq >= MAX_SEQ:
            raise AEADError("counter exhausted: rekey required")
        return self._prefix + self.seq.to_bytes(8, "big")

    def seal(self, plaintext, aad=b""):
        nonce = self._nonce()
        ct = self._aes.encrypt(nonce, plaintext, aad)
        self.last_nonce = nonce
        self.seq += 1
        return ct

    def open(self, ciphertext, aad=b""):
        """Decrypt with the NEXT expected sequence number. A replayed/reordered/forged record fails (nonce mismatch);
        a failed open does not advance the counter."""
        nonce = self._nonce()
        try:
            pt = self._aes.decrypt(nonce, ciphertext, aad)
        except InvalidTag as e:
            raise AEADError("record authentication failed") from e
        self.last_nonce = nonce
        self.seq += 1
        return pt
