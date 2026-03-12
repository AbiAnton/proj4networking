"""
Abigail Anton
Top comment here at some point
"""

import sys
import time
import json
import subprocess

def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Need 2 files to run\n")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # print("Input file:", input_file, " Output file:", output_file)

    domain_names = {}
    resolvers = []

    with open("public_dns_resolvers.txt") as f:
        for line in f:
            resolvers.append(line.strip())

    with open(input_file) as f:
        for line in f:
            domain = line.strip()
            scan_time = time.time()


            # Address lookups
            ipv4_addresses = set()
            ipv6_addresses = set()
            for resolver in resolvers:

                try: 
                    result = subprocess.check_output(["nslookup", domain, resolver],
                            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    result = result.split("\n")
                    for l in result:
                        if "Address:" in l and not ("#" in l): 
                            l = l.split("Address:",1)[1].strip()
                            if not (":" in l):
                                ipv4_addresses.add(l)
                            else:
                                ipv6_addresses.add(l)
                except subprocess.TimeoutExpired:
                    continue


            # HTTP lookups
            server = None
            insecure_http, redirect, hsts = False, False, False
            try:
                result = subprocess.check_output(["curl", "-I", "-L", "--max-redirs", "10", "http://" + domain],
                        timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                insecure_http = True
                result = result.split("\n")
                for l in result:
                    if "Server:" in l:
                        server = l.split("Server:",1)[1].strip()
                    elif "Location:" in l and "https" in l:
                        redirect = True
                    elif "Strict-Transport-Security" in l:
                        hsts = True
            except subprocess.TimeoutExpired:
                pass

            body = {
                "scan_time": scan_time,
                "ipv4_addresses" : list(ipv4_addresses),
                "ipv6_addresses" : list(ipv6_addresses),
                "http_server" : server,
                "insecure_http" : insecure_http,
                "redirect_to_https" : redirect,
                "hsts" : hsts
            }

            domain_names[domain] = body

    # Output file
    with open(output_file, "w") as f:
        json.dump(domain_names, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()