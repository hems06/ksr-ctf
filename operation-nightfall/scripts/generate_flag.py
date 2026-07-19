#!/usr/bin/env python3
"""
Operation Nightfall — Flag Generator
=====================================

Generates a randomized flag and updates the .env file for deployment.
Each deployment gets a unique flag to prevent flag sharing between teams.

Usage:
  python generate_flag.py                    # Generate and print
  python generate_flag.py --write            # Generate and write to .env
  python generate_flag.py --format custom    # Custom flag format
"""

import argparse
import hashlib
import os
import random
import string
import sys
import time


def generate_flag(seed=None, prefix="flag"):
    """Generate a unique, memorable CTF flag."""
    if seed:
        random.seed(seed)
    
    # Generate a flag that looks like it belongs to this challenge
    adjectives = [
        "n1ghtf4ll", "sh4d0w", "d4rkn3ss", "ph4nt0m", "sp3ct3r",
        "c0b4lt", "0bsid1an", "cr1ms0n", "v0rt3x", "n3bul4",
    ]
    
    verbs = [
        "br34ch3d", "pwn3d", "0wn3d", "h4ck3d", "ch41n3d",
        "3xpl01t3d", "byp4ss3d", "cr4ck3d", "d3f34t3d", "r00t3d",
    ]
    
    # Random hex suffix for uniqueness
    hex_suffix = ''.join(random.choices('0123456789abcdef', k=8))
    
    adj = random.choice(adjectives)
    verb = random.choice(verbs)
    
    return f"{prefix}{{{adj}_{verb}_{hex_suffix}}}"


def update_env_file(flag, env_path=".env"):
    """Update or create .env file with the new flag."""
    lines = []
    flag_updated = False
    
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            lines = f.readlines()
        
        for i, line in enumerate(lines):
            if line.startswith('FLAG_VALUE='):
                lines[i] = f'FLAG_VALUE={flag}\n'
                flag_updated = True
                break
    
    if not flag_updated:
        lines.append(f'FLAG_VALUE={flag}\n')
    
    with open(env_path, 'w') as f:
        f.writelines(lines)
    
    return env_path


def main():
    parser = argparse.ArgumentParser(
        description="Generate a randomized CTF flag for Operation Nightfall",
    )
    parser.add_argument(
        "--write", "-w",
        action="store_true",
        help="Write the flag to .env file",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file (default: .env)",
    )
    parser.add_argument(
        "--seed", "-s",
        default=None,
        help="Random seed for reproducible flags",
    )
    parser.add_argument(
        "--prefix", "-p",
        default="flag",
        help="Flag prefix (default: flag)",
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=1,
        help="Number of flags to generate (for batch deployment)",
    )

    args = parser.parse_args()

    for i in range(args.count):
        seed = f"{args.seed}_{i}" if args.seed else None
        flag = generate_flag(seed=seed, prefix=args.prefix)
        
        if args.write and i == 0:
            env_path = update_env_file(flag, args.env_file)
            print(f"[+] Flag written to {env_path}")
        
        print(f"[+] Flag {i+1}: {flag}")
        
        # Also print the SHA-256 for verification
        flag_hash = hashlib.sha256(flag.encode()).hexdigest()
        print(f"    SHA-256: {flag_hash}")


if __name__ == "__main__":
    main()
