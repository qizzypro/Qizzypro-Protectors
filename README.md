📦 Step 2: Run the Script
1️⃣ Save this script as something like:
``` nano ddos_defense.py```

2️⃣ Make sure you have these Python packages installed:
```pip install scapy rich psutil requests```

3️⃣ Run it:
```python3 ddos_defense.py```
✅ On first run, it will:


🛠 Step 3: Edit Configuration
Go to:
```cd config/config.json```
And change:

Interface (eth0 or your server’s real interface)

Thresholds (pps, mitigation pause, etc.)

Trusted IPs (your own admin IPs)

🚀 Summary
✔ Script self-creates config directory + file
✔ Protects against DDoS with real-time blocking
✔ Shows live VPS CPU, RAM, blocked IPs
✔ Batches blocked IPs to external firewall if configured
