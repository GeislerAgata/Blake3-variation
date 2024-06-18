from CPU_functions import find_hash_for_input

# Pobieranie input_text ze standardowego wejścia i wyznaczanie funkcji skrótu
while True:
    print("Provide input text for hash: [write exit to close]")
    input_text = input().strip()

    if input_text.lower() == 'exit':
        print("Exiting...")
        break

    input_data = find_hash_for_input(input_text)

    print(f"Hash for input {input_text}: {input_data}\n")