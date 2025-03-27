#!/usr/bin/env python3

import sys
import os
import random
import subprocess

FLIP_RATIO = 0.01
FLIP_ARRAY = [1 << i for i in range(8)]
NUM_ITERATIONS = 100000
CRASH_DIR = "crashes"
OPTIONS = [0,1]

MAGIC_VALS = [
    [0xFF],
    [0x7F],
    [0x00],
    [0xFF, 0xFF],           # 0xFFFF
    [0x00, 0x00],           # 0x0000
    [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
    [0x00, 0x00, 0x00, 0x00], # 0x00000000
    [0x00, 0x00, 0x00, 0x80], # 0x80000000
    [0x00, 0x00, 0x00, 0x40], # 0x40000000
    [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

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

def apply_magic(datos):
    flips_number = max(1, int((len(datos) - 14) * FLIP_RATIO))
    indexes = random.sample(range(8, len(datos) - 6), flips_number)

    for idx in indexes:
        picked_magic = random.choice(MAGIC_VALS)
        for offset, val in enumerate(picked_magic):
            if idx + offset < len(datos):
                datos[idx + offset] = val

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
    os.makedirs(CRASH_DIR, exist_ok=True)
    for i in range(NUM_ITERATIONS):
        if i % 100 == 0:
            sys.stdout.write(f"\rIteration {i} of {NUM_ITERATIONS}")
            sys.stdout.flush()
        option = random.choice(OPTIONS)
        #option = 1
        if option == 1:
            mutated_bytes = bit_flip(bytearray(bytes_pdf))
        else:
            mutated_bytes = apply_magic(bytearray(bytes_pdf))

        create_pdf(mutated_bytes)
        try:
            process = subprocess.Popen(
                ["pdfinfovul", "data/fuzzed.pdf"], 
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
           
            try:
                _, stderr = process.communicate(timeout=2)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
                returncode = -1
            

            if returncode == 139 or returncode == -11:
                print(f" [!!!] Crash detected in iteration {i}! con returncode {returncode}")
                crash_path = f"{CRASH_DIR}/crash_{i}_option{option}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)

            elif returncode == -1:
                print(f" [???] TIMEOUT in iteration {i}!")
                crash_path = f"timeout/crash_{i}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)

            else:
                stderr_str = stderr.decode('utf-8', errors='ignore').lower()
                if "segmentation fault" in stderr_str or "segmentation" in stderr_str:
                    print(f"[!!!] Crash detected in iteration {i}!")
                    crash_path = f"{CRASH_DIR}/crash_{i}_option{option}.pdf"
                    with open(crash_path, "wb") as f:
                        f.write(mutated_bytes)
        except Exception as e:
            print(f"Error ejecutando exif: {e}")

 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ruta_del_pdf>")
        sys.exit(1)
    
    pdf = sys.argv[1]
    bytes_pdf = read_pdf(pdf)

    if bytes_pdf is None:
        sys.exit(1)

    run_fuzzer(bytes_pdf)

