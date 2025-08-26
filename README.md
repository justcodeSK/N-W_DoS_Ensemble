<h1 align="center"> 🛡️ Network-Level DDoS and DoS Prediction Using Ensemble Learning Approach with Mitigation Strategies </h1>


<h2 align="center">🚀 AttackNetZero – DDoS, Dos Detection & Analysis System </h2>

## 📌 Project Overview
**AttackNetZero** is an academic **cybersecurity and ethical hacking project** developed using **Python + Django** for real-time **DoS/DDoS attack detection, mitigation, and traffic analysis**.  

This system integrates:
- A **VirtualBox testbed** for simulating real-world cyberattacks.
- **Packet sniffing & monitoring** using `scapy`, `pyshark`, and Linux network tools.
- **Machine Learning pipeline** with **stacking ensemble learning** for accurate classification.
- A **Django-based web interface** to make traffic analysis more user-friendly than CLI-only tools.
- **Admin/User role-based control** for security & monitoring.

---

## ⚙️ VirtualBox Setup

| VM Role           | OS              | Purpose                                                                 |
|-------------------|-----------------|-------------------------------------------------------------------------|
| 🖥 Guest 1        | Windows XP      | Victim machine (target of DoS/DDoS attacks).                           |
| 🐧 Guest 2        | Kali Linux      | Attacker machine – used to launch DoS/DDoS attacks (SYN Flood, etc.).   |
| 🔐 Guest 3        | Kali Linux      | Defender – runs **AttackNetZero Django app** for monitoring & detection.|

**Tools inside VMs**:  
- **Nmap** → used to scan ports/services and mimic real-world black hat hacker reconnaissance.  
- **Wireshark / TShark** → for packet capture & inspection.  
- **iptables** → for IP blocking/mitigation from within AttackNetZero.  

---

## ⚔️ Attack Types Implemented

The following **DoS/DDoS attacks** were simulated between Kali (attacker) and Windows XP (victim):

| Attack Type | Protocol | Description |
|-------------|----------|-------------|
| **SYN Flood** | TCP | Exploits TCP handshake by sending excessive SYN requests, exhausting resources. |
| **ACK Flood** | TCP | Floods target with ACK packets, bypassing firewall rules. |
| **RST Flood** | TCP | Sends many RST packets to reset existing connections. |
| **FIN Flood** | TCP | Uses TCP FIN flag to prematurely close connections. |
| **PSH Flood** | TCP | Sends PSH flag packets to overwhelm target buffers. |
| **UDP Flood** | UDP | Sends large numbers of UDP packets to random ports, causing resource exhaustion. |
| **ICMP Flood (Ping Flood)** | ICMP | Floods victim with ICMP Echo Requests (pings). |
| **Fragmentation Flood (Frag Flood)** | IP | Sends fragmented packets to overload reassembly buffers. |

✅ These traffic patterns were captured and stored for ML training/testing.

---

## 🧠 Machine Learning Pipeline

The ML pipeline was designed for **DDoS detection in real-time**:

1. **Preprocessing**
   - Merged multiple `.csv` network logs.
   - Cleaned labels and balanced dataset using **SMOTE**.
   - Label-encoded categorical features (e.g., Protocol).
   - Applied **StandardScaler** normalization and saved scaler (`scaler.pkl`).

2. **Hybrid Feature Selection**
   - Mutual Information.
   - Tree-Based Importance (XGBoost + Random Forest).
   - RFECV for feature elimination.

3. **Ensemble Learning (Stacking)**
   - **Base models**: XGBoost, KNN, SVM, MLP.
   - **Meta-model**: Random Forest.
   - Combined predictions for higher robustness.

4. **Hyperparameter Tuning**
   - Used `RandomizedSearchCV` for optimal parameters (neighbors, learning rate, layers, etc.).

5. **Evaluation Metrics**
   - Accuracy, Precision, Recall, F1-score.
   - Confusion Matrix analysis.
   - Stacked ensemble outperformed individual models.

---

## 🌐 Django Web Application – AttackNetZero

The web UI provides **user-friendly features** for cybersecurity researchers:

### 🔑 Role Management
- **Admin**
  - Approves new users.
  - Monitors user activity logs.
  - Can permanently delete malicious/unapproved users.
- **User**
  - Can perform CRUD operations (except deleting users).
  - Can capture & analyze network traffic.

### 📡 Features

| Feature | Description |
|---------|-------------|
| **Traffic Monitoring** | Capture live packets across dynamic interfaces (Ethernet, WiFi, Bluetooth). |
| **Traffic Saving** | Save packet logs in **JSON (lightweight)** and download for later. |
| **CSV Tools** | Upload, edit, merge CSVs for data analysis. |
| **Labeling** | Manually label captured traffic as attack/normal. |
| **Real-time Detection** | Red-packet visualization for detected attacks. |
| **Manual Detection** | Paste a single packet → classify with ML pipeline. |
| **Blocking** | Backend `iptables` integration allows one-click IP block. |
| **Mitigation Studies** | Built-in documentation of attack strategies & defenses. |
| **IP Tracker (Future Feature)** | Google Maps API mockup for attacker location tracking. |

---

## 📊 Dataset
- **Custom low-sample dataset** (<1350 samples).  
- Used for **academic showcase**.  
- Demonstrates feasibility but can be extended to larger datasets for production.  
- **Note**: More data = higher accuracy.  

---

## 🧪 Tools & Frameworks
- **Languages**: Python, Django  
- **Libraries**: Scikit-learn, XGBoost, KNN, SVM, MLP, Numpy, Pandas, Matplotlib  
- **Packet Tools**: Scapy, PyShark, Wireshark/TShark  
- **Security Tools**: iptables, Nmap  
- **Storage**: JSON for lightweight logs, CSV for analysis  
- **Visualization**: Matplotlib, Google Maps API  

---

## 📽️ Presentation
A Canva presentation is available here:  👉 [View Presentation](https://www.canva.com/design/DAGrLvjM8EM/EzZttgBOp__14OFiol62HQ/edit?utm_content=DAGrLvjM8EM&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton)

---

## ✅ Conclusion
AttackNetZero demonstrates a **full cycle cybersecurity tool**:
- Simulating **real DoS/DDoS attacks** in a controlled environment.  
- Capturing & labeling **network traffic**.  
- Training & deploying an **ensemble ML model**.  
- Providing a **web-based user interface** for real-time monitoring, detection, and mitigation.  

This makes it a strong **academic showcase project** and a base for future production-level cybersecurity platforms.

