#!/bin/bash

# Exit if any command fails
set -e

echo "🚀 Starting project setup..."

# Move to project root (where this script is located)
cd "$(dirname "$0")"

# Check Python version
if ! python3 --version | grep -q "3.10"; then
  echo "⚠️ Python 3.10 not found. Please install Python 3.10+ before running this script."
  exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
rm -rf djenv
python3 -m venv djenv

# Activate environment
source djenv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📦 Installing requirements..."
pip install -r requirements.txt

# Extra useful packages
echo "➕ Installing numba and pytest..."
pip install numba pytest

echo ""
echo "✅ Setup complete!"
echo "👉 To activate your environment, run:"
echo "   source djenv/bin/activate"
