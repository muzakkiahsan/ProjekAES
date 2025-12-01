# aes_backend.py

# ===========================================
#  AES core + SBOX44 backend
# ===========================================

AES_SBOX = [
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,
    205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,
    96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,
    224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,
    231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,
    186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,
    112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,
    225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,
    140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22,
]

SBOX44 = [
    99,205,85,71,25,127,113,219,63,244,109,159,11,228,94,214,
    77,177,201,78,5,48,29,30,87,96,193,80,156,200,216,86,
    116,143,10,14,54,169,148,68,49,75,171,157,92,114,188,194,
    121,220,131,210,83,135,250,149,253,72,182,33,190,141,249,82,
    232,50,21,84,215,242,180,198,168,167,103,122,152,162,145,184,
    43,237,119,183,7,12,125,55,252,206,235,160,140,133,179,192,
    110,176,221,134,19,6,187,59,26,129,112,73,175,45,24,218,
    44,66,151,32,137,31,35,147,236,247,117,132,79,136,154,105,
    199,101,203,52,57,4,153,197,88,76,202,174,233,62,208,91,
    231,53,1,124,0,28,142,170,158,51,226,65,123,186,239,246,
    38,56,36,108,8,126,9,189,81,234,212,224,13,3,40,64,
    172,74,181,118,39,227,130,89,245,166,16,61,106,196,211,107,
    229,195,138,18,93,207,240,95,58,255,209,217,15,111,46,173,
    223,42,115,238,139,243,23,98,100,178,37,97,191,213,222,155,
    165,2,146,204,120,241,163,128,22,90,60,185,67,34,27,248,
    164,69,41,230,104,47,144,251,20,17,150,225,254,161,102,70,
]

Nb = 4
Nk = 4
Nr = 10

def xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def add_round_key(state, round_key):
    return [s ^ rk for s, rk in zip(state, round_key)]

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Data kosong, tidak bisa unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding tidak valid")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding tidak konsisten")
    return data[:-pad_len]

# ===========================================
#  SUBBYTES + SHIFTROWS + MIXCOLUMNS
# ===========================================

INV_AES_SBOX = [0] * 256
for i, v in enumerate(AES_SBOX):
    INV_AES_SBOX[v] = i

INV_SBOX44 = [0] * 256
for i, v in enumerate(SBOX44):
    INV_SBOX44[v] = i

def sub_bytes_aes(state):
    return [AES_SBOX[b] for b in state]

def inv_sub_bytes_aes(state):
    return [INV_AES_SBOX[b] for b in state]

def sub_bytes_44(state):
    return [SBOX44[b] for b in state]

def inv_sub_bytes_44(state):
    return [INV_SBOX44[b] for b in state]

def shift_rows(state):
    return [
        state[0],  state[5],  state[10], state[15],
        state[4],  state[9],  state[14], state[3],
        state[8],  state[13], state[2],  state[7],
        state[12], state[1],  state[6],  state[11],
    ]

def inv_shift_rows(state):
    return [
        state[0],  state[13], state[10], state[7],
        state[4],  state[1],  state[14], state[11],
        state[8],  state[5],  state[2],  state[15],
        state[12], state[9],  state[6],  state[3],
    ]

def mix_single_column(col):
    col = col[:]
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)
    return col

def mix_columns(state):
    state = state[:]
    for i in range(0, 16, 4):
        col = state[i:i+4]
        state[i:i+4] = mix_single_column(col)
    return state

def inv_mix_columns(state):
    state = state[:]
    for i in range(0, 16, 4):
        a0, a1, a2, a3 = state[i:i+4]
        state[i+0] = gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^ gmul(a2, 0x0D) ^ gmul(a3, 0x09)
        state[i+1] = gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^ gmul(a2, 0x0B) ^ gmul(a3, 0x0D)
        state[i+2] = gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0E) ^ gmul(a3, 0x0B)
        state[i+3] = gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0E)
    return state

# ===========================================
#  KEY EXPANSION
# ===========================================

Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion_aes(key_bytes: bytes):
    assert len(key_bytes) == 16
    key_schedule = list(key_bytes)
    i = Nk
    while len(key_schedule) < 16 * (Nr + 1):
        temp = key_schedule[-4:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= Rcon[(i // Nk) - 1]
        for j in range(4):
            temp[j] ^= key_schedule[-16 + j]
        key_schedule.extend(temp)
        i += 1
    return key_schedule

def key_expansion_sbox44(key_bytes: bytes):
    assert len(key_bytes) == 16
    key_schedule = list(key_bytes)
    i = Nk
    while len(key_schedule) < 16 * (Nr + 1):
        temp = key_schedule[-4:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX44[b] for b in temp]
            temp[0] ^= Rcon[(i // Nk) - 1]
        for j in range(4):
            temp[j] ^= key_schedule[-16 + j]
        key_schedule.extend(temp)
        i += 1
    return key_schedule

# ===========================================
#  BLOCK ENCRYPT/DECRYPT
# ===========================================

def aes_encrypt_block_std(block: bytes, key_bytes: bytes) -> bytes:
    assert len(block) == 16
    assert len(key_bytes) == 16
    state = list(block)
    round_keys = key_expansion_aes(key_bytes)

    state = add_round_key(state, round_keys[:16])
    for r in range(1, Nr):
        state = sub_bytes_aes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[16*r:16*(r+1)])
    state = sub_bytes_aes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[16*Nr:16*(Nr+1)])
    return bytes(state)

def aes_decrypt_block_std(block: bytes, key_bytes: bytes) -> bytes:
    assert len(block) == 16
    assert len(key_bytes) == 16
    state = list(block)
    round_keys = key_expansion_aes(key_bytes)

    state = add_round_key(state, round_keys[16*Nr:16*(Nr+1)])
    state = inv_shift_rows(state)
    state = inv_sub_bytes_aes(state)
    for r in range(Nr-1, 0, -1):
        state = add_round_key(state, round_keys[16*r:16*(r+1)])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes_aes(state)
    state = add_round_key(state, round_keys[:16])
    return bytes(state)

def aes_encrypt_block_44(block: bytes, key_bytes: bytes) -> bytes:
    assert len(block) == 16
    assert len(key_bytes) == 16
    state = list(block)
    round_keys = key_expansion_sbox44(key_bytes)

    state = add_round_key(state, round_keys[:16])
    for r in range(1, Nr):
        state = sub_bytes_44(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[16*r:16*(r+1)])
    state = sub_bytes_44(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[16*Nr:16*(Nr+1)])
    return bytes(state)

def aes_decrypt_block_44(block: bytes, key_bytes: bytes) -> bytes:
    assert len(block) == 16
    assert len(key_bytes) == 16
    state = list(block)
    round_keys = key_expansion_sbox44(key_bytes)

    state = add_round_key(state, round_keys[16*Nr:16*(Nr+1)])
    state = inv_shift_rows(state)
    state = inv_sub_bytes_44(state)
    for r in range(Nr-1, 0, -1):
        state = add_round_key(state, round_keys[16*r:16*(r+1)])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes_44(state)
    state = add_round_key(state, round_keys[:16])
    return bytes(state)

# ===========================================
#  STRING API UNTUK FRONTEND
# ===========================================

def _normalize_key(key_str: str) -> bytes:
    key_bytes = key_str.encode("utf-8")
    if len(key_bytes) != 16:
        raise ValueError("Key AES harus tepat 16 byte (16 karakter ASCII sederhana).")
    return key_bytes

def encrypt_aes_std_str(plaintext: str, key_str: str) -> str:
    key_bytes = _normalize_key(key_str)
    data = plaintext.encode("utf-8")
    data = pkcs7_pad(data)
    ct = b""
    for i in range(0, len(data), 16):
        ct += aes_encrypt_block_std(data[i:i+16], key_bytes)
    return ct.hex()

def decrypt_aes_std_str(cipher_hex: str, key_str: str) -> str:
    key_bytes = _normalize_key(key_str)
    ct = bytes.fromhex(cipher_hex)
    if len(ct) % 16 != 0:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte (32 hex).")
    pt = b""
    for i in range(0, len(ct), 16):
        pt += aes_decrypt_block_std(ct[i:i+16], key_bytes)
    pt = pkcs7_unpad(pt)
    return pt.decode("utf-8", errors="strict")

def encrypt_aes_44_str(plaintext: str, key_str: str) -> str:
    key_bytes = _normalize_key(key_str)
    data = plaintext.encode("utf-8")
    data = pkcs7_pad(data)
    ct = b""
    for i in range(0, len(data), 16):
        ct += aes_encrypt_block_44(data[i:i+16], key_bytes)
    return ct.hex()

def decrypt_aes_44_str(cipher_hex: str, key_str: str) -> str:
    key_bytes = _normalize_key(key_str)
    ct = bytes.fromhex(cipher_hex)
    if len(ct) % 16 != 0:
        raise ValueError("Panjang ciphertext harus kelipatan 16 byte (32 hex).")
    pt = b""
    for i in range(0, len(ct), 16):
        pt += aes_decrypt_block_44(ct[i:i+16], key_bytes)
    pt = pkcs7_unpad(pt)
    return pt.decode("utf-8", errors="strict")
