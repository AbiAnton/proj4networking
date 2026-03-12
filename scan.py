"""
Abigail Anton
Part 1: Network Scanners
"""

import sys
import time
import json
import subprocess
import socket
import maxminddb

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
                    l_lower = l.lower()
                    if "server:" in l_lower:
                        server = l.split(":",1)[1].strip()
                    elif "location:" in l_lower and "https" in l_lower:
                        redirect = True
                    elif "strict-transport-security" in l_lower:
                        hsts = True
            except subprocess.TimeoutExpired:
                pass

            # TLS versions
            tls_versions = []
            tls_flags = [("SSLv2", "-ssl2"), ("SSLv3", "-ssl3"), ("TLSv1.0", "-tls1"), ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")]
            for i in range(len(tls_flags)):
                version = tls_flags[i][0]
                flag = tls_flags[i][1]

                try: 
                    result = subprocess.check_output(["openssl", "s_client", flag, "-connect", domain + ":443"], input=b'', timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                    if "CONNECTED" in result:
                        tls_versions.append(version)
                except subprocess.TimeoutExpired:
                    pass
                except subprocess.CalledProcessError:
                    pass

            # Root ca
            root_ca = None
            try:
                result = subprocess.check_output(["openssl", "s_client", "-connect", domain + ":443"], input=b'', timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                result = result.split("\n")

                for l in result:
                    if l.startswith("depth=2") and "O = " in l:
                        root_ca = l.split("O = ")[1].split(",")[0].strip()
                        break
            except subprocess.TimeoutExpired:
                pass
            except subprocess.CalledProcessError:
                pass

            # rdns
            rdns_names = []
            for add in ipv4_addresses:
                try:
                    result = subprocess.check_output(["nslookup", "-type=PTR", add], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    result = result.split("\n")

                    for l in result:
                        if "name" in l:
                            name = l.split("name =")[1].strip()
                            rdns_names.append(name)
                except subprocess.TimeoutExpired:
                    pass
                except subprocess.CalledProcessError:
                    pass

            # Rtt range
            rtt_range = None
            rtts = []
            ports = [80, 443, 22]

            for ip in ipv4_addresses:
                for port in ports:
                    try:
                        start = time.time()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        s.connect((ip, port))
                        s.close()
                        rtt = time.time() - start
                        rtt *= 1000 # convert to milliseconds
                        rtts.append(rtt)
                        break
                    except:
                        continue
            
            if rtts:
                rtt_range = [min(rtts), max(rtts)]

            # geo locations
            geo_locations = []
            try:
                with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
                    for ip in ipv4_addresses:
                        record = reader.get(ip)
                        if record:
                            city, state, country = "","",""

                            if "city" in record: 
                                city = record["city"]["names"]["en"]
                            if "subdivisions" in record and len(record["subdivisions"]) > 0:
                                state = record["subdivisions"][0]["names"]["en"]
                            if "country" in record:
                                country = record["country"]["names"]["en"]

                            location = ", ".join(filter(None, [city, state, country]))
                            if location and (location not in geo_locations):
                                geo_locations.append(location)

            except: 
                pass


            body = {
                "scan_time": scan_time,
                "ipv4_addresses" : list(ipv4_addresses),
                "ipv6_addresses" : list(ipv6_addresses),
                "http_server" : server,
                "insecure_http" : insecure_http,
                "redirect_to_https" : redirect,
                "hsts" : hsts,
                "tls_versions" : tls_versions,
                "root_ca" : root_ca,
                "rdns_names" : rdns_names,
                "rtt_range" : rtt_range,
                "geo_locations" : geo_locations
            }

            domain_names[domain] = body

    # Output file
    with open(output_file, "w") as f:
        json.dump(domain_names, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    main()