#!/usr/bin/env python3

import os
import datetime

def initialize_report(report_path):
    if os.path.exists(report_path):
        os.remove(report_path)
    return report_path

def generate_report(report_path, message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_message = f"{timestamp} - {message}"
    with open(report_path, "a") as f:
        f.write(report_message + "\n")

def final_part_report(report_path, stats):
    generate_report(report_path, "Fuzzing finalizado.")
    generate_report(report_path, "Resultados:")
    generate_report(report_path, f"Total de crashes: {stats['total_crashes']}")
    generate_report(report_path, f"Total de crashes únicos: {stats['total_unique']}")
    generate_report(report_path, f"Total de crashes repetidos: {stats['total_repeated']}")
    generate_report(report_path, f"Total de timeouts: {stats['total_timeout']}")
    generate_report(report_path, f"Total de crashes por bit flip: {stats['bit_flip_crashes']}")
    generate_report(report_path, f"Total de crashes por magia: {stats['magic_crashes']}")
    generate_report(report_path, f"Total de crashes por length: {stats['length_crashes']}")
    generate_report(report_path, "Funciones de crash encontradas:")
    for function in stats['crash_functions']:
        generate_report(report_path, f"Función: - {function}")