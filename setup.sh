#!/bin/bash

SCRIPT_NAME="idadump.py"
COMMAND_NAME="ida-dump"
INSTALL_DIR="/usr/local/bin"

# 1. Check for root permissions (needed to write to /usr/local/bin)
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

# 2. Check if the python script exists in the current directory
if [ ! -f "$SCRIPT_NAME" ]; then
    echo "Error: Could not find $SCRIPT_NAME in the current directory."
    exit 1
fi

echo "Installing $COMMAND_NAME to $INSTALL_DIR..."

# 3. Copy the file
cp "$SCRIPT_NAME" "$INSTALL_DIR/$COMMAND_NAME"

# 4. Make it executable
chmod +x "$INSTALL_DIR/$COMMAND_NAME"

echo "------------------------------------------------"
echo "Success! You can now run the tool from ANY folder."
echo ""
echo "Usage example:"
echo "  $COMMAND_NAME /path/to/my_binary"
echo "  $COMMAND_NAME ./crackme.exe"
echo ""
echo "Note: On new PCs, ensure you have run the IDA activation script:"
echo "  sudo python3 /opt/ida-9.0/idalib/python/py-activate-idalib.py"
echo "------------------------------------------------"