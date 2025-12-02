#!/bin/bash

# --- CONFIGURATION ---
# CHANGE THIS to your desired command name (e.g., 'idagent', 'idabridge', 're-ai')
COMMAND_NAME="revpal"

# Source files (must be in the current directory)
DUMP_SCRIPT="ida_dump.py"
ACTUATOR_SCRIPT="ida_actuator.py"

# Installation Paths
LIB_DIR="/usr/local/lib/$COMMAND_NAME"
BIN_PATH="/usr/local/bin/$COMMAND_NAME"

# ---------------------

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

# 2. Source Check
if [ ! -f "$DUMP_SCRIPT" ] || [ ! -f "$ACTUATOR_SCRIPT" ]; then
    echo "Error: Could not find $DUMP_SCRIPT or $ACTUATOR_SCRIPT in the current directory."
    exit 1
fi

echo "Installing $COMMAND_NAME..."

# 3. Create Lib Directory and Copy Scripts
mkdir -p "$LIB_DIR"
cp "$DUMP_SCRIPT" "$LIB_DIR/ida_dump.py"
cp "$ACTUATOR_SCRIPT" "$LIB_DIR/ida_actuator.py"

# Make them executable (just in case)
chmod +x "$LIB_DIR/ida_dump.py"
chmod +x "$LIB_DIR/ida_actuator.py"

# 4. Generate the Wrapper Script
cat <<EOF > "$BIN_PATH"
#!/bin/bash

# Define paths to the actual python tools
DUMP_TOOL="$LIB_DIR/ida_dump.py"
ACTUATOR_TOOL="$LIB_DIR/ida_actuator.py"

# Help Function
show_help() {
    echo "Usage: $COMMAND_NAME <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  dump   Analyze binary and generate report/xml"
    echo "         Usage: $COMMAND_NAME dump <binary> [flags]"
    echo ""
    echo "  load   Apply LLM-generated JSON changes to database"
    echo "         Usage: $COMMAND_NAME load <binary> <changes.json>"
    echo ""
    exit 1
}

# Check argument count
if [ \$# -lt 1 ]; then
    show_help
fi

SUBCOMMAND="\$1"
shift # Remove the subcommand from the argument list

case "\$SUBCOMMAND" in
    dump)
        # Pass all remaining arguments to the dump tool
        python3 "\$DUMP_TOOL" "\$@"
        ;;
    load)
        # Pass all remaining arguments to the actuator tool
        python3 "\$ACTUATOR_TOOL" "\$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Error: Unknown command '\$SUBCOMMAND'"
        show_help
        ;;
esac
EOF

# 5. Finalize Permissions
chmod +x "$BIN_PATH"

echo "------------------------------------------------"
echo "Success! Installed to $BIN_PATH"
echo ""
echo "Usage Examples:"
echo "  $COMMAND_NAME dump ./chall -p --disasm"
echo "  $COMMAND_NAME load ./chall changes.json"
echo ""
echo "Note: Files are stored in $LIB_DIR"
echo "------------------------------------------------"