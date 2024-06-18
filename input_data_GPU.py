from GPU_functions import find_input_for_hash, charset

target_hashes = [
    "D0 81 35 E0 01 E9 61 25 77 80 A4 FB 3A D2 99 08",  # for length 5    -> I#iA@
]

# Pobieranie target_hash z predefiniowanej zmiennej
for length, target_hash in enumerate(target_hashes, start=1):
    output_file = f"output_hash_5.txt"
    input_data = find_input_for_hash(target_hash, 5, charset, output_file)
    print(f"Input for hash {target_hash}: {input_data}\n")
    with open(output_file, 'a') as file:
        file.write(f"Input for hash {target_hash}: {input_data}\n")