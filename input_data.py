from CPU_functions import find_input_for_hash, charset

target_hashes = [
    "09 23 7E 6A 58 5A E2 95 DA DA 12 DF 52 53 98 95",  # for length 2    -> 2U
    "A2 BC 09 31 C9 69 3B 0F C6 46 E6 95 57 6A B2 95",  # for length 3    -> Y=N
    "9C A5 EB 00 81 21 0F E5 D1 C8 9A BE B6 44 91 76",  # for length 4    -> PO!-
    # "D0 81 35 E0 01 E9 61 25 77 80 A4 FB 3A D2 99 08",  # for length 5    -> I#iA@
    # "58 54 02 1A 13 79 C0 14 6B B9 B2 38 CA 17 0F 83",  # for length 6
    # "11 47 29 10 97 DA FC 8B 83 05 41 1F 00 76 13 69",  # for length 7
    # "D8 68 37 3A E7 C3 B8 0E 35 69 34 C7 35 51 1C AA"   # for length 8
]

# Pobieranie target_hash z predefiniowanej zmiennej
for length, target_hash in enumerate(target_hashes, start=1):
    output_file = f"output_hash_{length + 1}.txt"
    input_data = find_input_for_hash(target_hash, length + 1, charset, output_file)
    print(f"Input for hash {target_hash}: {input_data}\n")
    with open(output_file, 'a') as file:
        file.write(f"Input for hash {target_hash}: {input_data}\n")