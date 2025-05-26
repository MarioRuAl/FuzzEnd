#!/usr/bin/env python3

import sys
import os
import random
import subprocess
import signal
import glob

from utils import read_pdf, create_pdf
from mutators import bit_flip, apply_magic, mutate_pdf_length
import crashes
import reports
from evolver import fit_pool, mutate_pool
from basic_blocks import list_visited_offsets

NUM_ITERATIONS = 50000
CRASH_DIR = "final_coverage"
UNIQUE_DIR = os.path.join(CRASH_DIR, "unicos")
REPEATED_DIR = os.path.join(CRASH_DIR, "repetidos")
TIMEOUT_DIR = os.path.join(CRASH_DIR, "timeout")
INFORME_PATH = os.path.join(CRASH_DIR, "informe.txt")
COV_LOG_DIR = "cov_logs"
DYNAMORIO_ROOT = "/home/kali/DynamoRIO-Linux-11.3.0-1"
DRCOV_CLIENT     = os.path.join(DYNAMORIO_ROOT, "tools/lib64/release/libdrcov.so")
BINARY_PATH = "/usr/local/bin/pdfinfovul"
FUZZED_PATH = "data/fuzzed.pdf"

OPTIONS = [0,1,2] # 0: bit_flip, 1: magic, 2: length
MUTATORS = [bit_flip, apply_magic, mutate_pdf_length]

def run_fuzzer(pdf_path, bytes_pdf):
    for dir in (CRASH_DIR, UNIQUE_DIR, REPEATED_DIR, TIMEOUT_DIR, COV_LOG_DIR):
        os.makedirs(dir, exist_ok=True)

    reports.initialize_report(INFORME_PATH)
    reports.generate_report(INFORME_PATH, "Fuzzing iniciado.")
    reports.generate_report(INFORME_PATH, f"PDF de entrada: {pdf_path}")

    # Ctrl-C
    stop_flag = False
    def on_int(sig, frame):
        nonlocal stop_flag
        stop_flag = True
    signal.signal(signal.SIGINT, on_int)

    core = [bytes_pdf]
    corpus = []          # [(bytes, set(offsets))]
    pool = []            # [(bytes, trace)]
    samples = []         # [bytes]
    trace_global = set() # offsets ya vistos

    coverage_history = [] # tamaño de trace_global tras cada iteración
    new_blocks = []       # número de nuevos bloques por mutante
    total_cov = 0

    i = 0
    while i < NUM_ITERATIONS and not stop_flag:
        if i % 100 == 0:
            print(f"\rIteración {i}/{NUM_ITERATIONS}", end="", flush=True)
            print(f"[=] Iter {i}: Cobertura global = {total_cov} bloques")

        if not samples:
            fit_pool(core, corpus, trace_global, pool)
            mutate_pool(pool, samples, MUTATORS)

        mutated_bytes, mutation_type = samples.pop()
        create_pdf(mutated_bytes)

        for f in glob.glob(f"{COV_LOG_DIR}/drcov.*.log"):
            os.remove(f)
        
        subprocess.run([
            "drrun", "-root", DYNAMORIO_ROOT,
            "-c", DRCOV_CLIENT,
            "-logdir", COV_LOG_DIR,
             "--", BINARY_PATH, FUZZED_PATH
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        log = max(glob.glob(f"{COV_LOG_DIR}/drcov.*.log"), key=os.path.getmtime)
        cov = set(list_visited_offsets(log, module_name=os.path.basename(BINARY_PATH)))

        old_size = len(trace_global)
        trace_global |= cov

        total_cov = len(trace_global)
        coverage_history.append(total_cov)
        num_new = total_cov - old_size
        new_blocks.append(num_new)

        if num_new > 0:
            print(f"\n[+] Iter {i}: +{num_new} nuevos BBs (total={total_cov})")      

        try:
            process = subprocess.Popen(
                [BINARY_PATH, FUZZED_PATH], 
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
                crash_path = f"{CRASH_DIR}/crash_{i}_option{mutation_type}.pdf"
                with open(crash_path, "wb") as f:
                    f.write(mutated_bytes)

                function_name, is_repeated = crashes.classify_crash(crash_path, UNIQUE_DIR, REPEATED_DIR, mutation_type)                
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

            else:
                corpus.append((mutated_bytes, cov))

            i += 1

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