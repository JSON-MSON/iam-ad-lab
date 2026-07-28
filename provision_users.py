#!/usr/bin/env python3
import csv
import subprocess
import sys

with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        subprocess.run([
            "sudo", "samba-tool", "user", "create",
            row["username"], "TempPass123!",
            f"--given-name={row['given_name']}"
        ], check=True)
        subprocess.run([
            "sudo", "samba-tool", "user", "move",
            row["username"], row["ou"]
        ], check=True)
        print(f"Provisioned {row['username']} into {row['ou']}")
