<img width="3002" height="1882" alt="749953C7-C980-4A12-9409-5D0630D7462E" src="https://github.com/user-attachments/assets/3ccce975-1bf7-4f0b-abf7-01ae5248fd39" />
# 🛡️ macOS Network Intrusion Detection & Isolation System (NIDS)

A proactive, kernel-level network security tool developed for macOS to monitor live cyber threats (DDoS, Port Scans, Payload Injections) in real-time and automatically isolate attackers using the macOS native **`pfctl` (Packet Filter)** firewall.

---

## 🚀 Key Features

- **Continuous Background Daemon:** Programmed to run seamlessly as a persistent background process using `nohup`, executing with root permissions without requiring any terminal pop-ups.
- **Kernel-Level Packet Filtering:** Leverages `pfctl` to dynamically drop attacker packets at the OS kernel level, forcing an immediate **`Host seems down`** status on the attacker's terminal.
- **Multi-Vector Threat Detection:**
  - **DDoS Mitigation:** Tracks packet frequency per source IP to suppress high-burst rate volumetric attacks (`>20 Packets`).
  - **Reconnaissance Alert:** Instantly detects stealthy network mapping tools (`Nmap`) probing over 5 closed ports.
  - **Malicious Payload Inspection:** Decodes the `Raw Layer` of incoming packets to intercept live web exploits and script injections (e.g., `<script>`, `union select`).
- **Dynamic Whitelisting & Self-Protection:** Utilizes the `socket` library to auto-discover the Mac's own live local IP and critical global services (Google DNS `8.8.8.8`, Cloudflare `1.1.1.1`), mitigating any risk of a **Self-Blocking Error**.
- **Persistent Threat Logging:** Automatically timestamps and logs all active mitigations with granular failure/success metrics directly to a secure root path: `/Users/Shared/nids_blocked_ips.txt`.

---

## 🛠️ Architecture & Data Flow

```text
  [ Incoming Traffic ] 
           │
           ▼
   [ Interface: en0 ] ────► ( Scapy Raw Sniffer )
                                   │
                                   ▼
                       [ Packet Analysis Logic ]
                        /          │          \
                       /           │           \
               ( DDoS Check ) ( Port Scan ) ( Injection Check )
                       \           │           /
                        \          │          /
                                   ▼
                        [ Trigger Mitigation ]
                                   │
                                   ▼
                   [ Execute: macOS pfctl Firewall ]
                                   │
                                   ▼
             [ Attacker Isolated + Persistent Logging ]
```

---

## 📦 Tech Stack Used

- **Language:** Python 3
- **Libraries:** Scapy (Raw Packet Sniffing & Handling), Socket, Collections
- **OS Level Firewall:** macOS Packet Filter (`pfctl`)
- **Audit & Testing Tools:** Nmap (Network Mapper), Netcat (`nc`), `lsof`

---

## 💻 Quick Start & Deployment

### 1. Save the Core Script
Ensure your script file `nids_core.py` is present in your dedicated workspace directory.

### 2. Grant Network Driver (BPF) Access
Enable packet capturing for background daemons by adjusting the permissions of Berkeley Packet Filters:
```bash
sudo chmod 666 /dev/bpf*
```

### 3. Deploy to the Background Permanently
```bash
sudo nohup python3 nids_core.py > /dev/null 2>&1 &
```

### 4. Monitor Live Security Logs
```bash
tail -f /Users/Shared/nids_blocked_ips.txt
```

---

## 🎯 Technical Interview Preparation (Why pfctl?)

- **Why choose `pfctl` over application-level blocking?**
  `pfctl` operates directly within the operating system kernel. Dropping malicious frames here prevents them from exhausting user-space RAM and CPU cycles, ensuring system stability even under heavy DDoS duress.
- **How is self-blocking prevented?**
  The script incorporates a runtime host IP discovery loop that dynamically catches the system's own active interface identity and binds it safely to a protected data structure (Set).


  ### 👨‍💻 Developer's Reflection & Journey

Building this project was a challenging but immensely rewarding journey. Operating entirely 
independent of external mentorship, I encountered numerous technical hurdles, particularly 
regarding macOS kernel-level network permissions and background daemon management. However, 
refusing to yield to roadblocks taught me the true meaning of engineering resourcefulness.

In the rapidly evolving tech landscape of 2026, access to a laptop and an internet connection 
leaves zero room for excuses. While traditional academic curricula focus heavily on covering a 
fixed syllabus, real-world security challenges require an entirely different approach: a 
relentless mindset of continuous research, daily learning, and iterative building. 

Leveraging AI as a collaborative engineering partner, I realized that syntax is merely a tool, 
but the fundamental architecture and underlying logic must belong entirely to the developer. 
Ultimately, this project stands as a testament to self-taught persistence, proving that profound 
technical understanding is forged through hands-on debugging and breaking down complex systems 
independently.
