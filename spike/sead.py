#!/usr/bin/env python3
"""
sys-slp-client — SEAD RNG implementation (bit-exact from Pretendo wiki / Nintendo).

SEAD is Nintendo's internal standard library. The RNG uses a 4×u32 state with
xorshift-like generation. Used by ENL for game-specific key derivation.

Algorithm (from https://nintendo-wiki.pretendo.network/docs/sead.html):

Seed initialization (single u32 or 4×u32 array):
    multiplier = 0x6C078965
    temp = seed
    for i in 1..4:
        temp ^= temp >> 30
        temp = (temp * multiplier + i) & 0xFFFFFFFF
        state[i-1] = temp

u32() generation:
    temp = state[0]
    temp ^= (temp << 11) & 0xFFFFFFFF
    temp ^= temp >> 8
    temp ^= state[3]
    temp ^= state[3] >> 19
    state[0] = state[1]
    state[1] = state[2]
    state[2] = state[3]
    state[3] = temp
    return temp

uint(n): return (u32() * n) >> 32  (multiply-and-shift, no rejection sampling)
"""

import struct
from typing import List, Union


class SEADRNG:
    """
    SEAD Random Number Generator (bit-exact Nintendo implementation).

    From https://nintendo-wiki.pretendo.network/docs/sead.html
    """

    MULTIPLIER = 0x6C078965

    def __init__(self, seed: Union[int, List[int], tuple]):
        """
        Initialize RNG with seed.

        Args:
            seed: Either a single u32 (expanded to 4×u32) or 4×u32 array/tuple.
        """
        if isinstance(seed, int):
            # Single u32 seed: expand to 4×u32 using Nintendo's LCG-based init
            self._state = self._expand_seed(seed & 0xFFFFFFFF)
        elif isinstance(seed, (list, tuple)) and len(seed) == 4:
            self._state = [s & 0xFFFFFFFF for s in seed]
        else:
            raise ValueError("Seed must be a single u32 or 4×u32 array")

    def _expand_seed(self, seed: int) -> List[int]:
        """Expand single u32 seed to 4×u32 state (Nintendo's algorithm)."""
        temp = seed & 0xFFFFFFFF
        state = []
        for i in range(1, 5):
            temp ^= (temp >> 30)
            temp = (temp * self.MULTIPLIER + i) & 0xFFFFFFFF
            state.append(temp)
        return state

    def u32(self) -> int:
        """Generate next 32-bit random value (xorshift-like)."""
        s = self._state
        temp = s[0]
        temp ^= (temp << 11) & 0xFFFFFFFF
        temp ^= temp >> 8
        temp ^= s[3]
        temp ^= s[3] >> 19
        s[0] = s[1]
        s[1] = s[2]
        s[2] = s[3]
        s[3] = temp & 0xFFFFFFFF
        return temp

    def uint(self, n: int) -> int:
        """
        Return random integer in [0, n).

        Uses multiply-and-shift: (u32() * n) >> 32
        """
        if n <= 0:
            raise ValueError("n must be positive")
        return (self.u32() * n) >> 32

    def get_state(self) -> List[int]:
        """Return current 4×u32 state (copy)."""
        return self._state.copy()

    def set_state(self, state: List[int]) -> None:
        """Set 4×u32 state directly."""
        if len(state) != 4:
            raise ValueError("State must be 4×u32")
        self._state = [s & 0xFFFFFFFF for s in state]


def create_key_part(rng: SEADRNG, table: List[int]) -> int:
    """
    Generate 4 bytes of key using SEAD RNG and 64-entry u32 table.

    Returns 32-bit integer (4 bytes in little-endian order).
    """
    value = 0
    for _ in range(4):
        index = rng.uint(len(table))
        shift = rng.uint(4) * 8
        byte = (table[index] >> shift) & 0xFF
        value = (value << 8) | byte
    return value


def create_key(rng: SEADRNG, table: List[int], size: int) -> bytes:
    """
    Generate ENL key of given size using SEAD RNG and table.

    Args:
        rng: Initialized SEADRNG instance
        table: 64-entry list of u32 integers
        size: Key size in bytes (must be multiple of 4)

    Returns:
        Key as bytes (little-endian per 4-byte chunk)
    """
    if size % 4 != 0:
        raise ValueError("Key size must be multiple of 4")
    if len(table) != 64:
        raise ValueError("Table must have exactly 64 entries")

    key = b""
    for _ in range(size // 4):
        value = create_key_part(rng, table)
        key += struct.pack("<I", value)  # little-endian
    return key


# ---- Published test vectors (from kinnay/NintendoClients wiki) ----

SPLATOON2_SEED = 0xCEB9D8D9
SPLATOON2_TABLE = [
    0x56CB956F, 0x7B50EEC6, 0x234D1A63, 0x1C691A6B,
    0xD2D9C482, 0xCFE21965, 0x0B32DF99, 0xB32AFE44,
    0xB15DA3D7, 0x86588505, 0x4FC8CD8B, 0xC30F864B,
    0x08D4D3BE, 0xEFDEC6CA, 0x63A1D53F, 0xC545538D,
    0x715E27A2, 0x4818A005, 0x8C28D9F8, 0xC303EABF,
    0xF1D847ED, 0xE837F303, 0xE68981E8, 0x63E2F9BC,
    0xC320F7E1, 0x5E0B4084, 0x502B2A2D, 0x65D36579,
    0x0D169E46, 0x65AB445D, 0xFDF0678B, 0x26167D3E,
    0xFE5025A0, 0x04EB0EA8, 0xC048B044, 0xF858002E,
    0x6725F7D6, 0xD4086AA8, 0xF216DE10, 0x0F1807E6,
    0xD3614878, 0x34A2FEE6, 0xA69AE3DE, 0xED8518EF,
    0x6FCCB7A5, 0x7F8D0E40, 0x9B72BFA8, 0x87C669D4,
    0x5BF80652, 0x9A71383F, 0xBA3E7A7A, 0x1ABA65A3,
    0xA9A16DFF, 0xD07B9E3C, 0x11C9BD45, 0xF14A6D81,
    0x78516ECD, 0x53445C15, 0xC86E9942, 0x5501D2C9,
    0xD0D4ECB3, 0x38F5C341, 0xC4A16155, 0x42F1F406,
]

SMM2_SEED = 0x123
SMM2_TABLE = [
    0xB301CA48, 0x5E758911, 0xC2B349E2, 0xF9942930,
    0x447AEFC0, 0xB6B5DB5F, 0xEE116832, 0xB6940169,
    0x2503FC94, 0x3D74B448, 0x58411B2C, 0x4EC8C604,
    0x74157415, 0xEC5B582B, 0xBC93A6F7, 0xB463AF87,
    0x6B09D0C2, 0x5DA54788, 0x7C20F6D5, 0xD5967141,
    0xF03C24F1, 0x87D2A479, 0xFC3F7C08, 0x9A4506B7,
    0x8B4FA2A2, 0x99AC2EDE, 0x9E74DEDF, 0x2CB60318,
    0xDA1AEE9E, 0x2238F1DD, 0x1A825163, 0x86B03FE8,
    0x8BD35FBE, 0x6E80E100, 0x6681ACFA, 0x61C990BD,
    0x70F61D95, 0x19177A6A, 0x729AE3CE, 0x5FFBD958,
    0x9F217D87, 0x3D478023, 0x986690D6, 0x19D6AB9B,
    0x8D8F2063, 0x8CC8EF69, 0x20843E06, 0x8CA2C3FE,
    0x78DA6631, 0xB3A27DE4, 0xB2D71198, 0x28F0890F,
    0x83B089CE, 0x235D8901, 0x290C0723, 0x85184BFC,
    0x82E15C68, 0x4D3BD8B4, 0x0447FB2F, 0x434717F0,
    0xCBCD01EC, 0x58A09E59, 0x630588E1, 0x1886EBE6,
]

# Nintendo Switch Sports - seed is 4×u32 array (from wiki)
NSSPORTS_SEED = [0xBBA83443, 0xE71A66A7, 0x4CD442B7, 0x826BB7D2]
NSSPORTS_TABLE = [
    0x29C73999, 0xEB535E58, 0xEBDEAAAF, 0xD17F53BB,
    0x3D39F87C, 0x9D5D2692, 0xBC3C69BA, 0xD64FDB0F,
    0xF34C3C6E, 0x32747DA6, 0x704D9E1C, 0x211C89FD,
    0x62E3E591, 0xF34A7500, 0xE6F9852F, 0xF638F0AF,
    0xC0D167F8, 0xBD03A45B, 0x741CD8BC, 0xB4E7A948,
    0x73837FFE, 0x6A105B43, 0x25CE0644, 0x7E66F0A2,
    0x0E820251, 0x8B0B6430, 0x33E2873C, 0x4C6B55F7,
    0x3095BD83, 0x01216403, 0x080C2648, 0xE522BD4E,
    0xAA54B6C5, 0x8D6075F2, 0x0468733D, 0xE33FF3CB,
    0x1389BEF4, 0x8C6C1CA6, 0x9BD83551, 0x6F5280FE,
    0x0F135AEC, 0xACEDAA62, 0xB52820DD, 0xC27EA809,
    0x2BAB994F, 0xBCAC10DF, 0xA9F74FBB, 0xA1D61FBA,
    0xC1FD7744, 0xBE28EC40, 0x06883D39, 0xF553BAFE,
    0x7419160A, 0x0426243E, 0x62544F55, 0xA5979860,
    0x8461CA4C, 0x0F2B1E92, 0x03D5B082, 0x55CA5351,
    0x0F10DDBE, 0xE9289E0C, 0x63A6D889, 0x5AE05499,
]

# Published keys for verification (16 bytes each)
PUBLISHED_KEYS = {
    "splatoon2": bytes.fromhex("ee182a63e216cdb1f51ad4bed8cf6508"),
    "smm2": bytes.fromhex("667c18475889faab61f93ef1da180971"),
    "nssports": bytes.fromhex("48545a26643c254c39107cd1f8004453"),
}


def verify_published_keys() -> dict:
    """Verify ENL implementation against published keys."""
    results = {}

    # Splatoon 2
    rng = SEADRNG(SPLATOON2_SEED)
    key = create_key(rng, SPLATOON2_TABLE, 16)
    results["splatoon2"] = {
        "computed": key.hex(),
        "expected": PUBLISHED_KEYS["splatoon2"].hex(),
        "match": key == PUBLISHED_KEYS["splatoon2"],
    }

    # Super Mario Maker 2
    rng = SEADRNG(SMM2_SEED)
    key = create_key(rng, SMM2_TABLE, 16)
    results["smm2"] = {
        "computed": key.hex(),
        "expected": PUBLISHED_KEYS["smm2"].hex(),
        "match": key == PUBLISHED_KEYS["smm2"],
    }

    # Nintendo Switch Sports
    rng = SEADRNG(NSSPORTS_SEED)
    key = create_key(rng, NSSPORTS_TABLE, 16)
    results["nssports"] = {
        "computed": key.hex(),
        "expected": PUBLISHED_KEYS["nssports"].hex(),
        "match": key == PUBLISHED_KEYS["nssports"],
    }

    return results


if __name__ == "__main__":
    print("Verifying SEAD RNG + ENL key derivation against published keys...\n")
    results = verify_published_keys()
    for game, r in results.items():
        status = "PASS" if r["match"] else "FAIL"
        print(f"{game}: {status}")
        print(f"  computed: {r['computed']}")
        print(f"  expected: {r['expected']}")
        print()