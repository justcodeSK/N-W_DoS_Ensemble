#!/bin/bash
# ================================================================
# 🛡️ Network Security Setup Script
# ---------------------------------------------------------------
# This script installs Python dependencies, network monitoring tools,
# and security utilities required for DDoS/DoS detection & mitigation.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Note:
#   - Works on Debian/Ubuntu-based systems.
#   - Run with sudo for full functionality.
# ================================================================

# Exit immediately if a command fails
set -e

echo "🔄 Updating pip and core Python packages..."
python3 -m pip install --upgrade pip setuptools wheel

echo "📦 Installing Python dependencies..."
pip3 install django djangorestframework
pip3 install scapy pyshark psutil
pip3 install joblib numpy pandas scikit-learn xgboost matplotlib
pip3 install google-generativeai
pip3 install numba pytest bcc

echo "🐍 Ensuring scientific stack..."
pip3 install scikit-learn pandas matplotlib --upgrade

echo "🔧 Updating system packages..."
sudo apt update -y

echo "📡 Installing Wireshark and TShark..."
sudo apt install -y wireshark tshark
sudo usermod -aG wireshark $USER

echo "⚡ Applying Wireshark group changes (current shell only)..."
newgrp wireshark || true

echo "🛡️ Installing iptables-persistent for saving firewall rules..."
sudo apt install -y iptables-persistent
sudo netfilter-persistent save

echo "✅ Setup complete!"
echo "👉 Please restart your terminal or run 'newgrp wireshark' to apply Wireshark permissions."
