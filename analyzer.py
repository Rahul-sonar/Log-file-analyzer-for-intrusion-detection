import pandas as pd
import matplotlib.pyplot as plt
import re
from collections import Counter

with open("logs/auth.log", "r") as file:
    logs = file.readlines()

failed = []

for line in logs:
    if "Failed password" in line:
      failed.append(line)

invalid_users = []

for line in logs:
    if "Invalid user" in line:
       invalid_users.append(line)

ips = []

for line in failed:
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

    if match:
       ips.append(match.group(1))

ip_count = Counter(ips)
report_lines = []

print("=============== SOC ALERT REPORT ===============\n")

for ip, count in ip_count.items():
   if count >= 10:
     risk = "HIGH"
   elif count >= 5:
     risk = "MEDIUM"
   else:
     risk = "LOW"

   print(f"IP Address: {ip}")
   print(f"failed attempts: {count}\n")
   print(f"Risk level: {risk}\n")

   report_lines.append(
      f"IP: {ip}\nAttempts: {count}\nRisk: {risk}\n"
     )

with open("reports/incident_report.txt","w") as report:
   report.write("SOC INCIDENT REPORT\n")
   report.write("==================\n\n")

   for line in report_lines:
       report.write(line + "\n")

data = []

for ip, count in ip_count.items():
   if count>=10:
     risk = "HIGH"
   elif count>=5:
     risk = "MEDIUM"
   else:
     risk = "LOW"

   data.append([ip, count, risk])
df = pd.DataFrame(
data, columns=["IP Address", "Attempts", "Risk level"]
)

df.to_csv(
  "reports/ip_report.csv",
   index=False
)

print("CSV Report Generated!!")

plt.figure(figsize=(8,5))

plt.bar(
    df["IP Address"],
    df["Attempts"]
)

plt.title(
    "Failed Login Attempts by IP"
)

plt.xlabel(
    "IP Address"
)

plt.ylabel(
    "Failed Attempts"
)

plt.savefig(
    "reports/attack_graph.png"
)

print("Attack Graph Generated!!")


print("\n========== Invalid User Attacks ==========\n")
for entry in invalid_users:
    print(entry.strip())

total_failed = len(failed)
total_invalid = len(invalid_users)

print("\n========== Threat Summary ==========\n")
print(f"Failed login attempts:{total_failed}")
print(f"Invalid user attempts:{total_invalid}")
print(f"Unique suspicious IPs:{len(ip_count)}")
