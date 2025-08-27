# 🛡️ AttackNET ZERO – Web Project Features  

## ✨ Key Features  

- **📡 Real-Time Traffic Monitoring**  
  - Capture live packets using Scapy & PyShark.  
  - Supports multiple network interfaces.  
  - Displays live traffic in a responsive table.  

- **📊 Data Visualization**  
  - Real-time graph updates using **Chart.js**.  
  - Traffic statistics (packets/sec, byte rate, etc.).  
  - Interactive charts remain visible after monitoring stops.  

- **🔍 Filtering & Analysis**  
  - Filter traffic for specific devices (e.g., XP machine).  
  - Monitor both local and connected systems.  
  - Export traffic data to **CSV** for offline analysis.  

- **🤖 Machine Learning DDoS/DoS Detection**  
  - Trained with **Random Forest, SVM, KNN, MLP, and XGBoost**.  
  - Stacking Ensemble approach with optimized hyperparameters.  
  - Achieves **99%+ accuracy** on attack detection.  
  - Supports detection of attacks like:  
    - **DDoS, DoS Hulk, PortScan, GoldenEye, Slowloris, UDP Flood, TCP SYN Flood, etc.**  

- **🧪 Manual Testing & Prediction**  
  - Web form to manually input 22+ network flow features.  
  - Predicts attack type (DDoS/DoS/Normal).  

- **⚡ Mitigation Strategies**  
  - IP Blocking/Unblocking via **iptables integration**.  
  - Web form for blocking specific **source/destination IPs**.  
  - Live table of blocked IPs.  
  - Maintains a **history of blocked IPs**.  

- **📱 Modern UI/UX**  
  - Built with **Tailwind CSS** and cyber-themed design.  
  - Sidebar navigation with floating graph window.  
  - Mobile-friendly & responsive layout.  
  - Smooth background transitions with fixed cyber-style theme.    

- **📝 Reporting & Insights**  
  - AI-powered advanced reporting using **Gemini API**.  
  - JSON-based analysis converted into professional reports.  

- **⚙️ Deployment & Setup**  
  - Runs inside VirtualBox with **Kali Linux (attacker), XP (victim), Windows 10 (monitor)**.  
  - Dual network adapter setup (Internal + Bridged).  
  - Fully configurable in **Django Admin Panel**.  

---

## 🔑 Admin & User Login  

<table>
  <tr>
    <th>Role</th>
    <th>Login Credentials</th>
    <th>Access & Permissions</th>
  </tr>
  <tr>
    <td><b>👤 Admin</b></td>
    <td>
      <b>User ID:</b> <code>admin@gmail.com</code><br>
      <b>Password:</b> <code>Admin@123</code>
    </td>
    <td>
      - Full access to <b>configuration settings</b>, <b>attack logs</b>, and <b>system control</b>.<br>
      - Can <b>create new admins</b> from:<br>
        <i>Admin → Settings → (Top-right corner) Add Admin → Create Admin</i><br>
      - Can <b>approve / reject</b> new user registrations.<br>
      - Can <b>delete users</b> anytime.
    </td>
  </tr>
  <tr>
    <td><b>👥 User</b></td>
    <td>
      <b>User ID:</b> <i>Email Set by user</i><br>
      <b>Password:</b> <i>Set by user</i>
    </td>
    <td>
      - Users can sign up from the <b>Homepage → Create User</b> option.<br>
      - After signup, the account goes into <b>Pending Approval</b> state.<br>
      - <b>Admin approval</b> is required before login is enabled.<br>
      - Once approved, users can view <b>traffic stats</b> & <b>reports</b>.
    </td>
  </tr>
</table>

---

## 📸 Screenshots (To Be Added)
- [ ] Real-time traffic monitoring dashboard  
- [ ] Attack detection (ML prediction)  
- [ ] IP blocking/unblocking interface  
- [ ] Traffic charts & graphs
- [ ] CSV Edit & Tools

---

## 🚀 Future Enhancements  
- [ ] Advanced anomaly detection with Deep Learning (LSTM/Autoencoders).  
- [ ] Email/SMS alerts for critical attacks.  
- [ ] Cloud deployment (Docker + Kubernetes).  



# ⚙️Setups

This project demonstrates a **safe, isolated environment** for simulating DoS/DDoS attacks and defending against them using a Django-based detection and mitigation system.  

The setup is built on **VirtualBox** with three guest systems:  

- **Victim:** Windows XP  
- **Attacker:** Kali Linux  
- **Defender:** Windows 10/Linux running Django ML-based detection  

---

## ⚙️ VirtualBox Setup

### Step 1: Install VirtualBox and Guest OS
- Install [VirtualBox](https://www.virtualbox.org/).
- Create **three virtual machines**:
  - Windows XP (Victim)
  - Kali Linux (Attacker)
  - Windows 10/Linux/Kali Linux (Defender)

### Step 2: Configure Network Adapters for Kali Linux (Defender)
Each Defender should have **two adapters**:
- **Adapter 1 (Internal Network):**  
  - Name: `inet`  
  - Mode: *Internal Network*  
  - Used for communication between VMs.  

- **Adapter 2 (Bridged Adapter):**  
  - Used only on **Defender system** for internet access.  
  - Ensures **host and other real devices are not affected**.  

### Step 3: Install VBoxGuest Additions
On all VMs:
- Enable **bidirectional clipboard & drag/drop**.
- Create a **shared folder** (e.g., `SharedAttackNet`) between host and Kali Linux.
- Copy the **Django project** into Kali’s `~/home` directory.

---

## 🌐 IP Address Configuration

1. Assign **static IPs** on each VM (Internal Network Adapter):
   - Victim (XP): `192.168.100.10`
   - Attacker (Kali): `192.168.100.20`
   - Defender (Win10/Linux/Kali Linux): `192.168.100.30`

2. Verify connectivity using `ping`:
   ```bash
   ping 192.168.100.10   # From Kali to XP
   ping 192.168.100.30   # From XP to Defender
   ```
## 🖥️ System Roles
  - Victim: Windows XP

  - Open Task Manager → Monitor CPU & Network usage.

  - Observe traffic spikes during attacks.
    
    ### Attacker: Kali Linux

    Use hping3 to simulate attacks:
    ```bash
    sudo hping3 -S --flood -V -p 80 192.168.100.10   # SYN Flood
    sudo hping3 --udp -p 80 --flood 192.168.100.10   # UDP Flood
    sudo hping3 --icmp --flood 192.168.100.10        # ICMP Flood
    ```
    - Target: Victim (Windows XP).
  ### Defender: Windows 10/Linux/Kali Linux (Django ML Detection-AttackNETZERO)

  1. Move Django project into home directory using shared folder.

  2. Run setup script to install dependencies:
     ```bash
     chmod +x setup.sh
      ./setup.sh
     ```
  3. Start the Django project:
     ```bash
     python3 manage.py runserver 0.0.0.0:8000
     ```
  4. Open in browser: http://127.0.0.1:8000

  5. Features:

  - Real-time packet capture (using PyShark/Scapy).

  - ML-based attack detection (Random Forest/XGBoost).

  - Mitigation:

    - Block Attacker IP (iptables on Kali or XP Firewall).

    - Monitor system health in UI.
    
## 🔒 Mitigation Strategies

Defender system can block attacker using iptables (Commandline code) AttackNETZERO provides UI for this codes:
```bash
sudo iptables -A INPUT -s 192.168.100.20 -j DROP
```
- Victim system (XP) can use Windows Firewall rules to block attacker IP.

- Only windows systems needs manuel blocking in linux based system the UI based Blocking is implemented.

- Defender logs and visualization show attack detection in real-time.

## 📊 Project Workflow Summary

| System                   | Role            | Action                                                  |
| ------------------------ | --------------- | ------------------------------------------------------- |
| **Victim (XP)**          | Target          | Observe CPU/traffic spike under attack                  |
| **Attacker (Kali)**      | Launch Attacks  | Use `hping3` to send SYN/UDP/ICMP floods                |
| **Defender (Win/Linux)** | Protect Network | Run Django ML project, detect attacks, apply mitigation |

## ✅ Verification

Ensure all systems can ping each other before starting.

Run an attack → verify traffic on XP Task Manager.

Check Django UI → attack detection alert.

Apply mitigation → verify blocked traffic.

## 🚀 Next Steps

Automate mitigation in Django using iptables integration.

Extend detection models for multi-class attack classification.

Add reporting & visualization dashboards.

