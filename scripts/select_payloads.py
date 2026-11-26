#!/usr/bin/env python3
"""
Selects the attack payloads used by the AlertForge evaluation dataset.

Source: public SecLists payload lists (MIT licence), master branch as of 25 Nov 2026.
  SQLi: Fuzzing/Databases/SQLi/sqli.auth.bypass.txt, Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt
  XSS : Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt, XSS-RSNAKE.txt, XSS-BruteLogic.txt

Selection is independent of the detection rules: objective filters only, then a seeded random sample.
Usage: python scripts/select_payloads.py <folder with the downloaded source lists>
"""
import random
import sys
from pathlib import Path

SEED = 7
N = 30
OUT = Path("data/eval/payloads")

SQLI_FILES = ["sqli.auth.bypass.txt", "Generic-BlindSQLi.fuzzdb.txt"]
XSS_FILES = ["XSS-Jhaddix.txt", "XSS-RSNAKE.txt", "XSS-BruteLogic.txt"]


def load(folder, names):
    seen, out = set(), []
    for name in names:
        for line in (folder / name).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and line not in seen:
                seen.add(line)
                out.append(line)
    return out


def usable(p):
    # objective filters: ASCII only, 5..200 characters, not a bare word ("update", "delete")
    return p.isascii() and 5 <= len(p) <= 200 and not p.isalpha()


def main():
    folder = Path(sys.argv[1])
    rnd = random.Random(SEED)
    OUT.mkdir(parents=True, exist_ok=True)
    for name, files, fix in (("sqli", SQLI_FILES, True), ("xss", XSS_FILES, False)):
        pool = [p for p in load(folder, files) if usable(p)]
        if fix:  # some SQLi entries carry a placeholder for a delay value
            pool = [p.replace("__TIME__", "5") for p in pool]
        chosen = rnd.sample(pool, N)
        (OUT / f"{name}.txt").write_text("\n".join(chosen) + "\n", encoding="utf-8", newline="\n")
        print(f"{name}: pool={len(pool)} selected={len(chosen)}")


if __name__ == "__main__":
    main()
