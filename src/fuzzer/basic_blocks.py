#!/usr/bin/env python3
import struct

def list_visited_offsets(log_path, module_name=None):
    with open(log_path, 'rb') as f:
        for line in f:
            if line.startswith(b"Module Table"):
                break
        
        #Saltamos primera línea
        f.readline()

        module_id = None
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                return set()
            if line.startswith(b"BB Table"):
                f.seek(pos)
                break
            parts = [p.strip() for p in line.split(b',')]
            if len(parts) >= 7:
                idx = parts[0].decode(errors="ignore")
                path = parts[6].decode(errors="ignore")
                if module_name and path.endswith(module_name):
                    module_id = int(idx)

        header = f.readline().decode(errors="ignore").split()
        total = int(header[2])

        offsets = set()
        for _ in range(total):
            entry = f.read(16)
            if len(entry) < 16:
                break
            addr, _, mid = struct.unpack('<Q I I', entry)
            if module_id is None or mid == module_id:
                offsets.add(addr)

        return offsets