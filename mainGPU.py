import itertools
import numba
from numba import cuda
import numpy as np

test = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"


# Inicjalizacja danych funkcji bazowej - git
def initialize_state_and_block(state, block):
    # Stan (16 bajtów) dzielimy na ciąg 8 liczb 16-bitowych - big endian
    w = np.array([int.from_bytes(state[i:i + 2], 'big') for i in range(0, 16, 2)], dtype=np.uint16)

    # Blok (32 bajty) dzielimy na ciąg 16 liczb 16-bitowych - big endian
    m = np.array([int.from_bytes(block[i:i + 2], 'big') for i in range(0, 32, 2)], dtype=np.uint16)

    return w, m


# Przesunięcie cykliczne w lewo - GPU
@cuda.jit(device=True)
def rol(x, n, bits=16):
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)


# Stan wejściowy zmieniany jest na macierz 4x4 liczb 16-bitowych - git
def initialize_v(w, block_num):
    v = np.array([
        [w[0], w[1], w[2], w[3]],
        [w[4], w[5], w[6], w[7]],
        [0x03F4, 0x774C, 0x5690, 0xC878],
        [0, block_num, 0, 0]
    ], dtype=np.uint16)
    return v


# Funckaj pomocnicza zmieniająca wartości a b c d - GPU
@cuda.jit(device=True)
def G(a, b, c, d, x, y):
    a = (a + b + x) & 0xFFFF
    d = rol(d ^ a, 3, 16)
    c = (c + d) & 0xFFFF
    b = rol(b ^ c, 11, 16)
    a = (a + b + y) & 0xFFFF
    d = rol(d ^ a, 2, 16)
    c = (c + d) & 0xFFFF
    b = rol(b ^ c, 5, 16)
    return a, b, c, d


@cuda.jit
def round_kernel(v, m):
    tx = cuda.threadIdx.x
    if tx == 0:
        # Pionowe przekształcenia
        v[0][0], v[1][0], v[2][0], v[3][0] = G(v[0][0], v[1][0], v[2][0], v[3][0], m[0], m[1])
        v[0][1], v[1][1], v[2][1], v[3][1] = G(v[0][1], v[1][1], v[2][1], v[3][1], m[2], m[3])
        v[0][2], v[1][2], v[2][2], v[3][2] = G(v[0][2], v[1][2], v[2][2], v[3][2], m[4], m[5])
        v[0][3], v[1][3], v[2][3], v[3][3] = G(v[0][3], v[1][3], v[2][3], v[3][3], m[6], m[7])
        # Ukośne przekształcenia
        v[0][0], v[1][1], v[2][2], v[3][3] = G(v[0][0], v[1][1], v[2][2], v[3][3], m[8], m[9])
        v[0][1], v[1][2], v[2][3], v[3][0] = G(v[0][1], v[1][2], v[2][3], v[3][0], m[10], m[11])
        v[0][2], v[1][3], v[2][0], v[3][1] = G(v[0][2], v[1][3], v[2][0], v[3][1], m[12], m[13])
        v[0][3], v[1][0], v[2][1], v[3][2] = G(v[0][3], v[1][0], v[2][1], v[3][2], m[14], m[15])


def permute_m(m):
    # perm = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
    example_perm = [5, 8, 0, 2, 6, 11, 1, 4, 15, 12, 3, 9, 10, 7, 13, 14]
    return np.array([m[example_perm[i]] for i in range(16)], dtype=np.uint16)


def hash_function(message, block_num=0):
    # Inicjalny stan, później jeśli tekst jawny to kilka bloków, to stan poprzedniego bloku jest stanem wejściowym dla kolejnego bloku
    state = bytearray(16)

    blocks = [message[i:i + 32] for i in range(0, len(message), 32)]

    for block in blocks:
        w, m = initialize_state_and_block(state, bytearray(block))
        v = initialize_v(w, block_num)

        v_gpu = cuda.to_device(v)
        m_gpu = cuda.to_device(m)

        for _ in range(6):  # 6 rund
            round_kernel[1, 1](v_gpu, m_gpu)
            m_gpu = cuda.to_device(permute_m(m_gpu.copy_to_host()))

        v = v_gpu.copy_to_host()

        for i in range(4):
            w[i] ^= v[0][i] ^ v[2][i]
            w[i + 4] ^= v[1][i] ^ v[3][i]

        state = b''.join([np.frombuffer(x.tobytes(), dtype=np.uint16).view(dtype=np.uint8).tobytes() for x in w])
        block_num += 1

    return state


def parse_target_hash(target_hash):
    return bytes.fromhex(target_hash.replace(' ', ''))


def format_hex(data):
    hex_str = data.hex()
    return ' '.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))


def reverse_byte_pairs(data):
    reversed_data = bytearray()  # Tworzymy nowy obiekt bytearray
    for i in range(0, len(data), 2):
        if i + 1 < len(data):  # Sprawdzamy, czy istnieje następna para bajtów
            reversed_data.extend([data[i + 1], data[i]])  # Dodajemy odwrócone bajty do nowej tablicy
        else:
            reversed_data.append(data[i])  # Dodajemy pojedynczy bajt, jeśli istnieje nieparzysta liczba bajtów
    return reversed_data


def find_input_for_hash(target_hash, length, charset, output_file):
    with open(output_file, 'w') as file:
        target_hash = parse_target_hash(target_hash.replace(' ', ''))
        # print(hash_function(parse_target_hash(test)))

        for candidate in itertools.product(charset, repeat=length):
            ascii_codes = [ord(ch) for ch in candidate]
            message = bytes(ascii_codes)

            # file.write(f"Candidate: {''.join(candidate)} -> ASCII Codes: {ascii_codes}")
            print(f"Candidate: {''.join(candidate)} -> ASCII Codes: {ascii_codes}")

            if message == b" ":
                padded_message = bytes([0x80] + [0x00] * (16 - len(message) % 16))
            else:
                padded_message = message + bytes([0x80] + [0x00] * ((16 - len(message) % 16) - 1))

            result_hash = hash_function(padded_message)
            # result_hex_hash = format_hex(result_hash)

            # file.write(result_hex_hash + "\n\n")  # wynik -> 23 09 6a 7e 5a 58 95 e2 da da df 12 53 52 95 98

            if reverse_byte_pairs(result_hash) == bytearray(target_hash):
                return message.decode('ascii')
    return None


charset = " qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*-_=+([{<)]}>'\";:?,.\\/|"

target_hashes = [
     "09 23 7E 6A 58 5A E2 95 DA DA 12 DF 52 53 98 95",  # for length 2    -> 2U
     "A2 BC 09 31 C9 69 3B 0F C6 46 E6 95 57 6A B2 95",  # for length 3    -> Y=N
     "9C A5 EB 00 81 21 0F E5 D1 C8 9A BE B6 44 91 76",  # for length 4    -> PO!-
     "D0 81 35 E0 01 E9 61 25 77 80 A4 FB 3A D2 99 08",  # for length 5
     "58 54 02 1A 13 79 C0 14 6B B9 B2 38 CA 17 0F 83",  # for length 6
     "11 47 29 10 97 DA FC 8B 83 05 41 1F 00 76 13 69",  # for length 7
     "D8 68 37 3A E7 C3 B8 0E 35 69 34 C7 35 51 1C AA"   # for length 8
]

for length, target_hash in enumerate(target_hashes, start=1):
    output_file = f"output_hash_{length + 1}.txt"
    input_data = find_input_for_hash(target_hash, length + 1, charset, output_file)
    print(f"Input for hash {target_hash}: {input_data}\n")
    with open(output_file, 'a') as file:
        file.write(f"Input for hash {target_hash}: {input_data}\n")
