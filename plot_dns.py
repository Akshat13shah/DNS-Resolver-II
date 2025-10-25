import pandas as pd
import matplotlib.pyplot as plt

# Load DNS log
df = pd.read_csv("dns_log.csv")

# Filter first 10 domains
first10 = df['Domain'].unique()[:10]

# Prepare data for plotting
servers_visited = []
latencies = []

for domain in first10:
    subset = df[df['Domain'] == domain]
    servers_visited.append(subset.shape[0])
    latencies.append(subset['RTT'].sum())

# Plot number of DNS servers visited
plt.figure(figsize=(8,5))
plt.bar(first10, servers_visited)
plt.title("Number of DNS servers visited per query (first 10 URLs)")
plt.xlabel("Domain")
plt.ylabel("Servers Visited")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("servers_visited.png")
plt.show()

# Plot total latency per query
plt.figure(figsize=(8,5))
plt.bar(first10, latencies)
plt.title("Total latency per query (first 10 URLs)")
plt.xlabel("Domain")
plt.ylabel("Latency (ms)")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("latency.png")
plt.show()

import pandas as pd
import matplotlib.pyplot as plt

# Load DNS log
df = pd.read_csv("dns_log.csv")

# Filter first 10 domains
first10 = df['Domain'].unique()[:10]

# Prepare data for plotting
servers_visited = []
latencies = []

for domain in first10:
    subset = df[df['Domain'] == domain]
    servers_visited.append(subset.shape[0])
    latencies.append(subset['RTT'].sum())

# Plot number of DNS servers visited
plt.figure(figsize=(8,5))
plt.bar(first10, servers_visited)
plt.title("Number of DNS servers visited per query (first 10 URLs)")
plt.xlabel("Domain")
plt.ylabel("Servers Visited")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("servers_visited.png")
plt.show()

# Plot total latency per query
plt.figure(figsize=(8,5))
plt.bar(first10, latencies)
plt.title("Total latency per query (first 10 URLs)")
plt.xlabel("Domain")
plt.ylabel("Latency (ms)")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("latency.png")
plt.show()
