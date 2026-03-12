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
    
    print("Input file:", input_file, " Output file:", output_file)

    domain_names = {}
    resolvers = []

    with open("public_dns_resolvers.txt") as f:
        for line in f:
            resolvers.append(line.strip())

    with open(input_file) as f:
        for line in f:
            domain = line.strip()
            scan_time = time.time()

            addresses = set()
            for resolver in resolvers:

                try: 
                    result = subprocess.check_output(["nslookup", domain, resolver],
                    timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    result = result.split("\n")
                    for l in result:
                        # ipv4
                        if "Address:" in l and not ("#" in l) and not (":" in l):
                            addresses.add(l.split("Address:",1)[1].strip())
                except subprocess.TimeoutExpired:
                    continue

            body = {
                "scan_time": scan_time,
                "ipv4_addresses" : list(addresses)
            }

            domain_names[domain] = body

    # Output file
    with open(output_file, "w") as f:
        json.dump(domain_names, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()