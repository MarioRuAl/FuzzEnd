#!/usr/bin/env python3

import sys
import os
import random
import subprocess
import re
import shutil
import datetime

FLIP_RATIO = 0.01
FLIP_ARRAY = [1 << i for i in range(8)]
NUM_ITERATIONS = 100000
CRASH_DIR = "crashes"
UNIQUE_DIR = os.path.join(CRASH_DIR, "unicos")
REPEATED_DIR = os.path.join(CRASH_DIR, "repetidos")
TIMEOUT_DIR = os.path.join(CRASH_DIR, "timeout")
INFORME_PATH = os.path.join(CRASH_DIR, "informe.txt")
crash_functions = set()


OPTIONS = [0,1, 2] # 0: bit_flip, 1: magic, 2: length

#CONTADORES PARA EL INFORME FINAL
total_crashes = 0
total_unique = 0
total_repeated = 0
total_timeout = 0
bit_flip_crashes = 0
magic_crashes = 0
length_crashes = 0


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


def generate_report(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_message = f"{timestamp} - {message}"
    with open(INFORME_PATH, "a") as f:
        f.write(report_message + "\n")

def final_part_report():
    generate_report("Fuzzing finalizado.")
    generate_report("Resultados:")
    generate_report(f"Total de crashes: {total_crashes}")
    generate_report(f"Total de crashes únicos: {total_unique}")
    generate_report(f"Total de crashes repetidos: {total_repeated}")
    generate_report(f"Total de timeouts: {total_timeout}")
    generate_report(f"Total de crashes por bit flip: {bit_flip_crashes}")
    generate_report(f"Total de crashes por magia: {magic_crashes}")
    generate_report(f"Total de crashes por length: {length_crashes}")
    generate_report("Funciones de crash encontradas:")
    for function in crash_functions:
        generate_report(f"Función: - {function}")


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


def mutate_pdf_length(pdf_bytes):
    pdf_data = bytearray(pdf_bytes)
    length_pattern = rb'/Length\s+(\d+)\s+.*?stream[\r\n]'
    
    try:
        matches = list(re.finditer(length_pattern, pdf_data, re.DOTALL))
        if not matches:
            return pdf_bytes
        
        to_modify = random.sample(matches, min(len(matches), random.randint(1, max(1, len(matches) // 2))))
        
        for match in to_modify:
            try:
                current_length = int(match.group(1))
                
                technique = random.randint(1, 10)
                
                if technique == 1:
                    new_length = 0
                elif technique == 2:
                    new_length = -1 * random.randint(1, 1000)
                elif technique == 3:
                    new_length = max(0, current_length - random.randint(1, min(100, current_length)))
                elif technique == 4:
                    new_length = current_length + random.randint(1, 100)
                elif technique == 5:
                    new_length = current_length * random.randint(2, 1000)
                elif technique == 6:
                    new_length = 2**31 - 1
                elif technique == 7:
                    new_length = 65535
                elif technique == 8:
                    new_length = current_length + 1
                elif technique == 9:
                    new_length = -2**31
                else:
                    new_length = random.randint(0, max(1000, current_length * 2))
                
                new_length_bytes = str(new_length).encode()
                
                start_pos = match.start(1)
                end_pos = match.end(1)
                pdf_data[start_pos:end_pos] = new_length_bytes
                
            except ValueError:
                continue
            
        return bytes(pdf_data)
    
    except Exception as e:
        print(f"Error en mutate_pdf_length: {e}")
        return pdf_bytes


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

    return f"{'Repetido' if is_repeated else 'Único'}: {function_name}", is_repeated


def run_fuzzer(pdf_path, bytes_pdf):
    global total_crashes, total_unique, total_repeated, total_timeout, bit_flip_crashes, magic_crashes, length_crashes

    os.makedirs(CRASH_DIR, exist_ok=True)
    os.makedirs(UNIQUE_DIR, exist_ok=True)
    os.makedirs(REPEATED_DIR, exist_ok=True)
    os.makedirs(TIMEOUT_DIR, exist_ok=True)

    if os.path.exists(INFORME_PATH):
        os.remove(INFORME_PATH)

    generate_report("Fuzzing iniciado.")
    generate_report(f"PDF de entrada: {pdf_path}")

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

                binary_path = "/usr/local/bin/pdfinfovul"  
                total_crashes += 1
                function_name, is_repeated = classify_crash(crash_path, binary_path)

                if is_repeated: 
                    total_repeated += 1
                else:
                    total_unique += 1

                if option == 0:
                    bit_flip_crashes += 1
                elif option == 1:
                    magic_crashes += 1
                else:
                    length_crashes += 1

                print(f"→ {function_name}")

                if not is_repeated:
                    generate_report(f"Crash en iteración {i} - {function_name}")
                

            elif returncode == -1:
                print(f" [???] TIMEOUT in iteration {i}!")
                crash_path = f"{TIMEOUT_DIR}/crash_{i}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)
                total_timeout += 1
                generate_report(f"Timeout en iteración {i}")

        except Exception as e:
            print(f"Error ejecutando pdfinfo: {e}")

    final_part_report()


 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ruta_del_pdf>")
        sys.exit(1)
    
    pdf = sys.argv[1]
    bytes_pdf = read_pdf(pdf)

    if bytes_pdf is None:
        sys.exit(1)
	
    run_fuzzer(pdf, bytes_pdf)
