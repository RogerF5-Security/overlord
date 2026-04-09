#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║               PROJECT OVERLORD  v1.0                         ║
║         Offensive Recon Pipeline Orchestrator                ║
║                                                              ║
║  Stack: CustomTkinter · asyncio · SQLite3                    ║
║  Phases: Subfinder → HTTPX → Masscan/Nmap → Nuclei/FFUF      ║
╚══════════════════════════════════════════════════════════════╝

Uso:
    python overlord.py

Dependencias Python:
    pip install customtkinter

Herramientas Kali requeridas:
    subfinder, httpx, masscan, nmap, nuclei, ffuf
    (opcional: amass)
"""
import sys
import os

# Asegurar que el paquete es importable
sys.path.insert(0, os.path.dirname(__file__))

def main():
    try:
        import customtkinter
    except ImportError:
        print("[!] customtkinter no está instalado.")
        print("    Instalar con: pip install customtkinter")
        sys.exit(1)

    from overlord.gui.app import launch
    launch()


if __name__ == "__main__":
    main()
