#!/usr/bin/env python3

import random
import re

FLIP_RATIO = 0.01
FLIP_ARRAY = [1 << i for i in range(8)]

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