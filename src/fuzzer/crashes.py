#!/usr/bin/env python3

import os
import re
import shutil
import subprocess

#CONTADORES PARA EL INFORME FINAL
crash_functions = set()
total_crashes = 0
total_unique = 0
total_repeated = 0
total_timeout = 0
bit_flip_crashes = 0
magic_crashes = 0
length_crashes = 0


def get_crash_function(crash_file, binary_path="/usr/local/bin/pdfinfovul"):
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


def classify_crash(crash_path, unique_dir, repeated_dir, mutation_type):
    global total_crashes, total_unique, total_repeated, bit_flip_crashes, magic_crashes, length_crashes
    
    function_name = get_crash_function(crash_path)
    base_name = os.path.basename(crash_path)
    is_repeated = False
    
    if function_name in crash_functions:
        target_path = os.path.join(repeated_dir, base_name)
        is_repeated = True
        total_repeated += 1
    else:
        crash_functions.add(function_name)
        target_path = os.path.join(unique_dir, base_name)
        total_unique += 1
    
    total_crashes += 1
    
    if mutation_type == 0:
        bit_flip_crashes += 1
    elif mutation_type == 1:
        magic_crashes += 1
    elif mutation_type == 2:
        length_crashes += 1
    
    shutil.move(crash_path, target_path)
    return function_name, is_repeated

def manage_timeout(crash_path, timeout_dir):
    global total_timeout
    total_timeout += 1
    shutil.move(crash_path, os.path.join(timeout_dir, os.path.basename(crash_path)))


def get_crash_stats():
    return {
        "total_crashes": total_crashes,
        "total_unique": total_unique,
        "total_repeated": total_repeated,
        "total_timeout": total_timeout,
        "bit_flip_crashes": bit_flip_crashes,
        "magic_crashes": magic_crashes,
        "length_crashes": length_crashes,
        "crash_functions": crash_functions
    }