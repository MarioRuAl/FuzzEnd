#!/usr/bin/env python3

import sys
import os
import random
import subprocess
import re
import shutil

FLIP_RATIO = 0.01
FLIP_ARRAY = [1 << i for i in range(8)]
NUM_ITERATIONS = 100000
CRASH_DIR = "crashes"
UNIQUE_DIR = os.path.join(CRASH_DIR, "unicos")
REPEATED_DIR = os.path.join(CRASH_DIR, "repetidos")
TIMEOUT_DIR = os.path.join(CRASH_DIR, "timeout")
crash_functions = set()


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

def get_crash_function(crash_file, binary_path):
    try:
        gdb_script = "gdb_commands.txt"
        with open(gdb_script, "w") as f:
            f.write(f"file {binary_path}\n")
            f.write(f"run {crash_file}\n")
            f.write("bt 3\n")
            f.write("quit\n")
        
        cmd = ["gdb", "-batch", "-x", gdb_script]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists(gdb_script):
            os.remove(gdb_script)
        
        output = result.stdout + result.stderr
        if "SIGSEGV" in output or "segmentation fault" in output.lower():
            frame_match = re.search(r'#0\s+(?:0x[0-9a-f]+\s+in\s+)?([^\s\(]+)', output)
            if frame_match:
                return frame_match.group(1)
            else:
                return "Función de fallo no encontrada"
        else:
            return "No hay segfault"
        
    except Exception as e:
        print(f"Error al obtener la función del crash: {e}")
        return "Error de procesamiento"

def classify_crash(crash_path, binary_path):
    function_name = get_crash_function(crash_path, binary_path)
    base_name = os.path.basename(crash_path)
    is_repeated = False
    
    if function_name in crash_functions:
        target_path = os.path.join(REPEATED_DIR, base_name)
        is_repeated = True
    else:
        crash_functions.add(function_name)
        target_path = os.path.join(UNIQUE_DIR, base_name)
    
    shutil.move(crash_path, target_path)

    return f"{'Repetido' if is_repeated else 'Único'}: {function_name}"


def run_fuzzer(bytes_pdf):
    os.makedirs(CRASH_DIR, exist_ok=True)
    os.makedirs(UNIQUE_DIR, exist_ok=True)
    os.makedirs(REPEATED_DIR, exist_ok=True)
    os.makedirs(TIMEOUT_DIR, exist_ok=True)


    for i in range(NUM_ITERATIONS):
        if i % 100 == 0:
            sys.stdout.write(f"\rIteration {i} of {NUM_ITERATIONS}")
            sys.stdout.flush()
            
        option = random.choice(OPTIONS)
        # option = 0
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

                binary_path = "/usr/local/bin/pdfinfovul"  
                classification = classify_crash(crash_path, binary_path)
                print(f"→ {classification}")
                

            elif returncode == -1:
                print(f" [???] TIMEOUT in iteration {i}!")
                crash_path = f"{TIMEOUT_DIR}/crash_{i}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)

            else:
                stderr_str = stderr.decode('utf-8', errors='ignore').lower()
                if "segmentation fault" in stderr_str or "segmentation" in stderr_str:
                    print ("Extra")
                    # print(f"[!!!] Crash detected in iteration {i}!")
                    # crash_path = f"{CRASH_DIR}/crash_{i}_option{option}.pdf"
                    # with open(crash_path, "wb") as f:
                    #     f.write(mutated_bytes)
        except Exception as e:
            print(f"Error ejecutando pdfinfo: {e}")

 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ruta_del_pdf>")
        sys.exit(1)
    
    pdf = sys.argv[1]
    bytes_pdf = read_pdf(pdf)

    if bytes_pdf is None:
        sys.exit(1)
	
    run_fuzzer(bytes_pdf)

