#!/usr/bin/env python3
"""
sys-slp-client — ENL key derivation (thin wrapper over SEAD RNG).

Provides a clean API for deriving Pia LAN/LDN game keys from seed + table.
"""

from sead import SEADRNG, create_key


# Game-specific ENL parameters (from kinnay/NintendoClients wiki)
# Format: {game_id: (seed, table)}
# seed: single u32 or [u32, u32, u32, u32]
# table: list of 64 u32 integers

GAME_PARAMS = {
    # Published keys (for verification)
    "splatoon2": (
        0xCEB9D8D9,
        [
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
        ],
    ),
    "smm2": (
        0x123,
        [
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
        ],
    ),
    "nssports": (
        [0xBBA83443, 0xE71A66A7, 0x4CD442B7, 0x826BB7D2],
        [
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
        ],
    ),
    # Games with seed+table but no published key (for derivation)
    # Add as discovered from RE / wiki
    # "acnh": (seed, table),
    # "acnh_island": (seed, table),
}


# Published keys for verification (16 bytes each)
PUBLISHED_KEYS = {
    "splatoon2": bytes.fromhex("ee182a63e216cdb1f51ad4bed8cf6508"),
    "smm2": bytes.fromhex("667c18475889faab61f93ef1da180971"),
    "nssports": bytes.fromhex("48545a26643c254c39107cd1f8004453"),
}


def derive_key(game_id: str, key_size: int = 16) -> bytes:
    """
    Derive ENL key for a game.

    Args:
        game_id: Game identifier (must be in GAME_PARAMS)
        key_size: Key size in bytes (default 16, must be multiple of 4)

    Returns:
        Derived key as bytes

    Raises:
        KeyError: If game_id not in GAME_PARAMS
        ValueError: If key_size not multiple of 4
    """
    if game_id not in GAME_PARAMS:
        raise KeyError(f"Unknown game: {game_id}. Available: {list(GAME_PARAMS.keys())}")

    seed, table = GAME_PARAMS[game_id]
    rng = SEADRNG(seed)
    return create_key(rng, table, key_size)


def verify_published() -> dict:
    """Verify ENL derivation against all published keys."""
    results = {}
    for game_id, expected_key in PUBLISHED_KEYS.items():
        derived = derive_key(game_id, len(expected_key))
        results[game_id] = {
            "match": derived == expected_key,
            "derived": derived.hex(),
            "expected": expected_key.hex(),
        }
    return results


def add_game_params(game_id: str, seed, table: list) -> None:
    """Register new game parameters (for games without published keys)."""
    if len(table) != 64:
        raise ValueError("Table must have exactly 64 entries")
    GAME_PARAMS[game_id] = (seed, table)


if __name__ == "__main__":
    print("ENL Key Derivation — Verification\n")
    results = verify_published()
    all_pass = True
    for game, r in results.items():
        status = "PASS" if r["match"] else "FAIL"
        if not r["match"]:
            all_pass = False
        print(f"{game}: {status}")
        print(f"  derived: {r['derived']}")
        print(f"  expected: {r['expected']}")
        print()

    print(f"All tests: {'PASS' if all_pass else 'FAIL'}")