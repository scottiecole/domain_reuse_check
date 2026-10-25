#!/usr/bin/env python3
"""
domain_reuse_check.py
Finds domain accounts sharing the same NT hash (password reuse) in an NTDS
dump produced by impacket's secretsdump.py.

Prompts for: NTDS file, export file, minimum group size, include blank hash.
Exports a text report (same format as the console) plus a CSV written
alongside the export file:
    <export>.csv

Default export is <NTDS file name>_domain_reuse.txt next to the NTDS file
(e.g. /path/to/ntds.txt -> /path/to/ntds_domain_reuse.txt).

Notes:
  - Password history: if the dump was taken with -history, entries like
    user_history0 are counted as separate accounts, so a user who reused an
    old password shows up as a shared hash between user and user_history0.
  - Account status isn't checked; disabled accounts are included.
  - Compare against local SAM dumps with hash_reuse_check.py.

Expects secretsdump.py-format lines:
    DOMAIN\\username:RID:LMHASH:NTHASH:::
"""

import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime

# NT hash for an empty/blank password - always shows up in real dumps
# (disabled accounts, etc.) and usually isn't an interesting finding on its own.
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


def ask_yes_no(prompt, default=False):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        ans = input(f"{prompt} {suffix}: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print(f"{RED}Enter y or n.{RESET}")


# ---------------------------------------------------------------- progress

def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {pct:6.1%}  {label:<47}")
    sys.stdout.flush()


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- parsing

def parse_ntds_line(line):
    """Returns (username, nt_hash) or None if the line can't be parsed."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    # Standard format: username:RID:LMHASH:NTHASH:::
    if len(parts) < 4:
        return None
    nt_hash = parts[3].lower()
    if len(nt_hash) != 32:
        return None
    return parts[0], nt_hash


def load_ntds(ntds_path):
    """Returns dict: nt_hash -> list of domain usernames."""
    total_bytes = os.path.getsize(ntds_path)
    hash_to_users = defaultdict(list)
    bytes_read = total_lines = parsed = 0

    print(f"\n{BOLD}[*] Reading NTDS dump ({fmt_size(total_bytes)}){RESET}")
    with open(ntds_path, "rb") as f:
        for raw in f:
            total_lines += 1
            bytes_read += len(raw)
            result = parse_ntds_line(raw.decode("utf-8", errors="ignore"))
            if result:
                parsed += 1
                username, nt_hash = result
                hash_to_users[nt_hash].append(username)
            if total_lines % 2000 == 0:
                progress_bar(bytes_read, total_bytes,
                             f"{fmt_size(bytes_read)} / {fmt_size(total_bytes)}")
    progress_bar(total_bytes, total_bytes, "done")
    print(f"\n[*] Parsed {parsed}/{total_lines} lines, {len(hash_to_users)} unique hashes")
    return hash_to_users, parsed


def find_shared(hash_to_users, min_count, include_empty):
    print(f"\n{BOLD}[*] Finding hashes shared by {min_count}+ accounts{RESET}")
    items = list(hash_to_users.items())
    groups = {}
    step = max(1, len(items) // 200)
    for i, (h, users) in enumerate(items):
        if len(users) >= min_count and (include_empty or h != EMPTY_NT_HASH):
            groups[h] = users
        if i % step == 0:
            progress_bar(i, len(items), f"{i}/{len(items)} hashes")
    progress_bar(len(items), len(items), "done")
    print()
    # Biggest password-reuse clusters first
    return sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)


# ---------------------------------------------------------------- reporting

class Tee:
    """Writes to the console (with color) and the export file (without)."""

    def __init__(self, fh):
        self.fh = fh

    def __call__(self, text="", color=""):
        print(f"{color}{text}{RESET}" if color else text)
        self.fh.write(text + "\n")


def write_report(out, groups, min_count):
    out()
    out("=== Domain <-> Domain Password Reuse ===", BOLD)
    out(f"[*] {len(groups)} hash(es) shared by {min_count}+ accounts\n")
    for h, users in groups:
        flag = "  <-- BLANK PASSWORD" if h == EMPTY_NT_HASH else ""
        out(f"NT Hash: {h}{flag}", RED)
        out(f"  Shared by {len(users)} accounts:")
        for u in users:
            out(f"    - {u}")
        out()
    if not groups:
        out("[*] No password reuse found matching the criteria.\n", GREEN)


def write_csv(csv_path, groups):
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["nt_hash", "account_count", "is_blank_password", "accounts"])
        for h, users in groups:
            w.writerow([h, len(users), h == EMPTY_NT_HASH, "; ".join(users)])


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}Domain Password Reuse Checker{RESET}\n")

    # --- NTDS file (full path) ---
    ntds_file = clean_path(input("NTDS dump file (full path): "))
    while not os.path.isfile(ntds_file):
        ntds_file = clean_path(input(f"{RED}Not found.{RESET} NTDS dump file (full path): "))

    # --- export file (full path) ---
    ntds_base = os.path.splitext(os.path.basename(ntds_file))[0]
    default_out = os.path.join(os.path.dirname(ntds_file), f"{ntds_base}_domain_reuse.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    while export_file == ntds_file:
        print(f"{RED}Export can't be the NTDS file itself.{RESET}")
        export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    csv_file = os.path.splitext(export_file)[0] + ".csv"

    # --- minimum group size ---
    min_count = input("Minimum accounts sharing a hash [2]: ").strip() or "2"
    while not (min_count.isdigit() and int(min_count) >= 2):
        min_count = input(f"{RED}Enter a number 2 or higher.{RESET} Minimum [2]: ").strip() or "2"
    min_count = int(min_count)

    include_empty = ask_yes_no("Include blank-password hash (31d6cfe0...)?", default=False)

    start = time.time()
    hash_to_users, parsed = load_ntds(ntds_file)
    groups = find_shared(hash_to_users, min_count, include_empty)

    with open(export_file, "w", encoding="utf-8") as fh:
        fh.write(f"Domain Password Reuse - {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        fh.write(f"NTDS file: {ntds_file}\n")
        fh.write(f"Minimum group size: {min_count}\n")
        fh.write(f"Blank hash included: {include_empty}\n")
        fh.write("=" * 80 + "\n")
        write_report(Tee(fh), groups, min_count)

    write_csv(csv_file, groups)

    affected = sum(len(u) for _, u in groups)
    print("-" * 80)
    print(f"[*] {len(groups)} shared hash(es) covering {affected} of {parsed} accounts "
          f"({time.time() - start:.1f}s)")
    print(f"\n[+] Report: {export_file}")
    print(f"[+] CSV:    {csv_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
