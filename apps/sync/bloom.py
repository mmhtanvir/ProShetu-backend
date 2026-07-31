"""
Minimal Bloom filter for sync set-reconciliation (architecture §3.4, §8).

The client sends a Bloom filter of event_ids it already holds; the server
returns only events NOT in that filter (plus honors an explicit want-list to
repair false positives). This is the same reconciliation the mesh performs
peer-to-peer, so the backend is "just another peer" running one code path.

We reuse the client's exact parameters (m bits, k hashes) by carrying them in
the request, and derive k independent hashes from a single BLAKE2b digest
(Kirsch–Mitzenmacher double hashing) so client and server agree bit-for-bit.
"""
import hashlib


class BloomFilter:
    def __init__(self, m_bits: int, k: int, raw: bytes | None = None):
        if m_bits <= 0 or k <= 0:
            raise ValueError("invalid bloom parameters")
        self.m = m_bits
        self.k = k
        nbytes = (m_bits + 7) // 8
        if raw is None:
            self.bits = bytearray(nbytes)
        else:
            if len(raw) != nbytes:
                raise ValueError("bloom byte length mismatch")
            self.bits = bytearray(raw)

    def _indices(self, item: str):
        d = hashlib.blake2b(item.encode(), digest_size=16).digest()
        h1 = int.from_bytes(d[:8], "big")
        h2 = int.from_bytes(d[8:], "big") | 1  # ensure odd, better distribution
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, item: str):
        for idx in self._indices(item):
            self.bits[idx >> 3] |= (1 << (idx & 7))

    def __contains__(self, item: str) -> bool:
        return all(
            self.bits[idx >> 3] & (1 << (idx & 7))
            for idx in self._indices(item)
        )

    @classmethod
    def from_hex(cls, m_bits: int, k: int, hex_str: str) -> "BloomFilter":
        return cls(m_bits, k, bytes.fromhex(hex_str)) if hex_str else cls(m_bits, k)
