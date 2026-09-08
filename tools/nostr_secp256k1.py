"""
Pure-Python secp256k1 x-only pubkey derivation + NIP-19 npub bech32 encoding.

Used only at BUILD TIME (spec #24, sub-issue #26) by gen_event_profile.py to
derive the per-event x-only pubkey baked into the generated event_profile.h.
This is deliberately NOT part of the on-device runtime pipeline: the ROM's
own C99 Schnorr *signing* port (secp256k1, #29) is separate, later work.
Only the one-shot build-time pubkey derivation lives here.

Scalar multiplication and the bech32 codec below are the standard secp256k1
/ BIP-173 algorithms; correctness is pinned by known-answer vectors from
BIP-340, asserted in tools/pipeline_test/main.c's test_pubkey_known_answer().
"""

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def _mod_inv(a, m):
    return pow(a, m - 2, m)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _mod_inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _mod_inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def derive_xonly_pubkey(privkey_bytes):
    """
    privkey_bytes: 32-byte raw private key.
    Returns: 32-byte x-only public key (the x coordinate of privkey * G).

    Note: BIP-340 keygen flips the private key (d -> n - d) when d*G has an
    odd y, so that *signing* nonces line up with the implicit even-y
    convention. That flip does not change the x coordinate of d*G (point
    negation only flips y), so it is irrelevant for pubkey derivation alone
    and is correctly omitted here -- this function only derives the pubkey,
    never signs (#29 is separate, later work).
    """
    d = int.from_bytes(privkey_bytes, "big")
    if not (0 < d < N):
        raise ValueError("private key out of range [1, n-1]")
    point = scalar_mult(d, G)
    return point[0].to_bytes(32, "big")


# --- NIP-19 npub bech32 encoding (BIP-173 bech32, not bech32m) -------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, data_bytes):
    data = _convertbits(list(data_bytes), 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def npub_from_xonly_pubkey(pubkey_bytes):
    return bech32_encode("npub", pubkey_bytes)
