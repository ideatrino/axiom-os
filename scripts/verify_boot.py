#!/usr/bin/env python3
"""
AXIOM OS full verification suite.
Usage: python3 scripts/verify_boot.py [--capture]

With --capture: boots AXIOM in QEMU (20s), captures output, verifies.
Without --capture: reads from stdin.
"""
import sys, os, subprocess, signal, time

CHECKPOINTS = [  # all must pass
    ("SHA-256 self-test",            "e3b0c442"),
    ("HMAC-SHA-256 implementation",  "CORRECT"),
    ("ChaCha20 self-test",           "CORRECT"),
    ("SHOT 7 CHECKPOINT PASSED",     "KNP theorem"),
    ("SHOT 9 CHECKPOINT PASSED",     "0x00"),
    ("SHOT 10 CHECKPOINT PASSED",    "VALID"),
    ("SHOT 11 CHECKPOINT PASSED",    "ACCEPTED"),
    ("Chain verification",           "PASSED"),
    ("SHOT 12",                      "FULLY OPERATIONAL"),
    ("IRET",                         "ring 3"),
]

def verify(log: str) -> bool:
    print("AXIOM OS Boot Checkpoint Verifier")
    print("=" * 52)
    all_ok = True
    for keyword, also in CHECKPOINTS:
        found = keyword in log and also in log
        mark  = "PASS" if found else "FAIL"
        if not found:
            all_ok = False
        print(f"  [{mark}]  {keyword}")
    print("=" * 52)
    if all_ok:
        print("ALL CHECKPOINTS PASSED -- AXIOM OS boot verified.")
    else:
        print("SOME CHECKPOINTS FAILED -- check boot output.")
    return all_ok

if "--capture" in sys.argv:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_file = "/tmp/axiom_verify_out.txt"
    err_file = "/tmp/axiom_verify_err.txt"

    print("Booting AXIOM OS (20s timeout)...")
    with open(out_file, "w") as fout, open(err_file, "w") as ferr:
        proc = subprocess.Popen(
            ["cargo", "run", "--package", "boot"],
            stdout=fout, stderr=ferr,
            cwd=root,
            preexec_fn=os.setsid,  # own process group so we can kill QEMU too
        )
        time.sleep(20)
        # Kill the entire process group (cargo + QEMU)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)

    with open(out_file) as f: stdout = f.read()
    with open(err_file)  as f: stderr = f.read()
    log = stdout + stderr
    ok = verify(log)
    sys.exit(0 if ok else 1)
else:
    log = sys.stdin.read()
    ok = verify(log)
    sys.exit(0 if ok else 1)
