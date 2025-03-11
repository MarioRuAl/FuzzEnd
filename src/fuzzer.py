#!/usr/bin/env python3

import sys
import os
import random
import subprocess

FLIP_RATIO = 0.01
FLIP_ARRAY = [1 << i for i in range(8)]
NUM_ITERATIONS = 10000

def read_pdf(pdf):
    try:
        with open(pdf, "rb") as f:
            datos = bytearray(f.read())
        return datos
    except Exception as e:
        print(f"Error al leer el PDF: {e}")
        return None

def bit_flip(datos):
    flips_number = max(1, int((len(datos) - 14) * FLIP_RATIO))
    indexes = random.sample(range (8, len(datos) - 6), flips_number)

    for i in indexes:
        datos[i] ^= random.choice(FLIP_ARRAY)

    return datos



def create_pdf(datos):
    path = "data/fuzzed.pdf"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(datos)
    except Exception as e:
        print(f"Error al escribir el PDF: {e}")


def run_fuzzer(bytes_pdf):
    for i in range(NUM_ITERATIONS):
        if i % 100 == 0:
            print(f"Iteration {i} of {NUM_ITERATIONS}")

        mutated_bytes = bit_flip(bytes_pdf)
        create_pdf(mutated_bytes)

        # Ejecutar pdfinfo
        result = subprocess.run(["pdfinfo", "data/fuzzed.pdf"], capture_output=True, text=True)
        stderr_output = result.stderr.lower()

        # Guardar PDFs corruptos que generen un segfault o core dump
        if "segmentation fault" in stderr_output or "core dumped" in stderr_output:
            print(f"[!!!] Crash detected in iteration {i}!")
            os.system(f"cp {"data/fuzzed.pdf"} {"crashes"}/crash_{i}.pdf")



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ruta_del_pdf>")
        sys.exit(1)
    
    pdf = sys.argv[1]
    bytes_pdf = read_pdf(pdf)

    if bytes_pdf is None:
        sys.exit(1)
    

    run_fuzzer(bytes_pdf)

    # mutated_bytes = bit_flip(bytes_pdf)
    # create_pdf(mutated_bytes)