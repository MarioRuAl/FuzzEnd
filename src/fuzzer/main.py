#!/usr/bin/env python3

import sys
import os
import random
import subprocess

from utils import read_pdf, create_pdf
from mutators import bit_flip, apply_magic, mutate_pdf_length
import crashes
import reports

NUM_ITERATIONS = 1000
CRASH_DIR = "crashes"
UNIQUE_DIR = os.path.join(CRASH_DIR, "unicos")
REPEATED_DIR = os.path.join(CRASH_DIR, "repetidos")
TIMEOUT_DIR = os.path.join(CRASH_DIR, "timeout")
INFORME_PATH = os.path.join(CRASH_DIR, "informe.txt")

OPTIONS = [0,1, 2] # 0: bit_flip, 1: magic, 2: length

def run_fuzzer(pdf_path, bytes_pdf):
    os.makedirs(CRASH_DIR, exist_ok=True)
    os.makedirs(UNIQUE_DIR, exist_ok=True)
    os.makedirs(REPEATED_DIR, exist_ok=True)
    os.makedirs(TIMEOUT_DIR, exist_ok=True)

    reports.initialize_report(INFORME_PATH)

    reports.generate_report(INFORME_PATH, "Fuzzing iniciado.")
    reports.generate_report(INFORME_PATH, f"PDF de entrada: {pdf_path}")

    for i in range(NUM_ITERATIONS):
        if i % 100 == 0:
            sys.stdout.write(f"\rIteration {i} of {NUM_ITERATIONS}")
            sys.stdout.flush()
            
        option = random.choice(OPTIONS)
        # option = 2
        if option == 0:
            mutated_bytes = bit_flip(bytearray(bytes_pdf))
        elif option == 1:
            mutated_bytes = apply_magic(bytearray(bytes_pdf))
        else:
            mutated_bytes = mutate_pdf_length(bytearray(bytes_pdf))

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

                function_name, is_repeated = crashes.classify_crash(crash_path, UNIQUE_DIR, REPEATED_DIR, option)                
                f"{'Repetido' if is_repeated else 'Único'}: {function_name}"
                print(f"{'Repetido' if is_repeated else 'Único'} → {function_name}")

                if not is_repeated:
                    reports.generate_report(INFORME_PATH, f"Crash en iteración {i} - {function_name}")
                

            elif returncode == -1:
                print(f" [???] TIMEOUT in iteration {i}!")
                crash_path = f"{TIMEOUT_DIR}/crash_{i}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)
                crashes.manage_timeout(crash_path, TIMEOUT_DIR)
                reports.generate_report(INFORME_PATH, f"Timeout en iteración {i}")

        except Exception as e:
            print(f"Error ejecutando pdfinfo: {e}")

    reports.final_part_report(INFORME_PATH, crashes.get_crash_stats())


 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ruta_del_pdf>")
        sys.exit(1)
    
    pdf = sys.argv[1]
    bytes_pdf = read_pdf(pdf)

    if bytes_pdf is None:
        print("Error al leer el archivo PDF")
        sys.exit(1)
	
    run_fuzzer(pdf, bytes_pdf)