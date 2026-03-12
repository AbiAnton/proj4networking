"""
Abigail Anton
Part 2: Report
"""

import sys
import json
import texttable

def main():
    if len(sys.argv) != 3:
        sys.stderr.write("Need 2 files to run\n")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
     
    with open(input_file) as f:
        data = json.load(f)

    output = ""

    # 1
    for domain, info in data.items():
        output += "=" * 50 + "\n"
        output += domain + "\n"
        output += "=" * 50 + "\n"
        for key, val in info.items():
            if isinstance(val, list):
                parts = []
                for v in val:
                    parts.append(str(v))
                val = ", ".join(parts)
            output += " " + key + ": " + str(val) + "\n"
        output += "\n"

    # 2
    rtt_list = []
    for domain, info in data.items():
        rtt_list.append((info["rtt_range"][0], domain, info))
    rtt_list.sort()

    t = texttable.Texttable()
    t.header(["Domain", "Min RTT (ms)", "Max RTT (ms)"])
    for min_rtt, domain, info in rtt_list:
        t.add_row(
            [domain, round(info["rtt_range"][0], 2), round(info["rtt_range"][1],2)]
        )
    output += t.draw() + "\n"

    # 3
    ca_counts = {}
    for domain, info in data.items():
        ca = info["root_ca"]
        if ca:
            ca_counts[ca] = ca_counts.get(ca, 0) + 1

    ca_list = []
    for ca, count in ca_counts.items():
        ca_list.append((count, ca))
    ca_list.sort(reverse=True)

    t = texttable.Texttable()
    t.header(["Root CA", "Count"])
    for count, ca in ca_list:
        t.add_row([ca, count])
    output += t.draw() + "\n"

    with open(output_file, "w") as f:
        f.write(output)

    # 4, basically the same as 3
    server_counts = {}
    for domain, info in data.items():
        server = info["http_server"]
        if server:
            server_counts[server] = server_counts.get(server, 0) + 1

    server_list = []
    for server, count in server_counts.items():
        server_list.append((count, server))
    server_list.sort(reverse=True)

    t = texttable.Texttable()
    t.header(["Web Server", "Count"])
    for count, server in server_list:
        t.add_row([server, count])
    output += t.draw() + "\n"

    with open(output_file, "w") as f:
        f.write(output)

if __name__ == "__main__":
    main()