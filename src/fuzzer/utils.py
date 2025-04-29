#!/usr/bin/env python3

import os

def read_pdf(pdf):
    try:
        with open(pdf, "rb") as f:
            datos = bytearray(f.read())
        return datos
    except Exception as e:
        print(f"Error al leer el PDF: {e}")
        return None

def create_pdf(datos):
    path = "data/fuzzed.pdf"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(datos)
    except Exception as e:
        print(f"Error al escribir el PDF: {e}")