#!/usr/bin/env python3
import sys
import os
import argparse
import json
import shutil
import time

# --- Dependency Check ---
try:
    import idapro
    import ida_hexrays
    import ida_auto
    import ida_loader
    import ida_funcs
    import ida_bytes
    import ida_ida
    import idc
    import ida_name
    import ida_typeinf
    import ida_kernwin
except ImportError:
    print("\n[!] Error: 'idalib' not found/activated.")
    sys.exit(1)

def backup_database(target_path):
    """Creates a timestamped backup of the database before modification."""
    if not os.path.exists(target_path):
        return False
    
    timestamp = int(time.time())
    backup_path = f"{target_path}.{timestamp}.bak"
    try:
        shutil.copy2(target_path, backup_path)
        print(f"[*] Safety Backup created: {backup_path}")
        return True
    except Exception as e:
        print(f"[!] Backup failed: {e}")
        return False

def handle_rename(action):
    """Renames a function or global address."""
    addr = int(action['address'], 16)
    name = action['name']
    
    # Check if address exists
    if not ida_bytes.is_loaded(addr):
        print(f"[!] Skip Rename: Address {hex(addr)} is not valid.")
        return

    # SN_NOWARN: Don't ask user, just do it
    # SN_NOCHECK: Allow weird characters if necessary
    success = idc.set_name(addr, name, idc.SN_NOWARN)
    if success:
        print(f"[+] Renamed {hex(addr)} -> {name}")
    else:
        print(f"[-] Failed to rename {hex(addr)} to {name} (Name might already exist)")

def handle_comment(action):
    """
    Sets a comment in Disassembly AND attempts to set it in Pseudocode.
    """
    addr = int(action['address'], 16)
    comment = action['content']
    is_repeatable = action.get('repeatable', False)
    
    # 1. Standard Disassembly Comment
    success = idc.set_cmt(addr, comment, 1 if is_repeatable else 0)
    if success:
        print(f"[+] Comment added at {hex(addr)} (ASM)")
    else:
        print(f"[-] Failed to comment at {hex(addr)} (ASM)")

    # 2. Hex-Rays Pseudocode Comment
    try:
        func = ida_funcs.get_func(addr)
        if func and ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                tl = ida_hexrays.treeloc_t()
                tl.ea = addr
                tl.itp = ida_hexrays.ITP_SEMI
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                print(f"[+] Comment synced to Hex-Rays at {hex(addr)}")
    except Exception as e:
        pass

def handle_struct(action):
    """
    Parses a C-style struct definition and adds it to Local Types.
    """
    c_def = action['definition'].strip()
    name = action.get('name', 'unknown_struct')
    
    # FIX: Append semicolon if missing
    if not c_def.endswith(';'):
        c_def += ';'
    
    til = ida_typeinf.get_idati()
    if not til:
        print(f"[!] Error: Could not access Type Library.")
        return

    # PT_TYP: Parse types, PT_SIL: Silent
    errors = ida_typeinf.parse_decls(til, c_def, None, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    
    if errors == 0:
        print(f"[+] Successfully parsed struct: {name}")
    else:
        print(f"[-] Failed to parse struct {name}. Syntax error in C definition.")

def handle_set_type(action):
    """
    Applies a C-style type definition/prototype to an address.
    """
    addr = int(action['address'], 16)
    c_decl = action['definition'].strip()
    
    # FIX: Append semicolon if missing
    if not c_decl.endswith(';'):
        c_decl += ';'
    
    if not ida_bytes.is_loaded(addr):
        print(f"[!] Skip Type: Address {hex(addr)} is not valid.")
        return

    til = ida_typeinf.get_idati()
    if not til:
        return

    tinfo = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tinfo, til, c_decl, ida_typeinf.PT_SIL):
        # Use apply_tinfo for better compatibility in IDA 9
        if ida_typeinf.apply_tinfo(addr, tinfo, ida_typeinf.TINFO_DEFINITE):
            print(f"[+] Applied type to {hex(addr)}")
        else:
            print(f"[-] Failed to apply type at {hex(addr)} (Collision or invalid target)")
    else:
        print(f"[-] Failed to parse type string: '{c_decl}'")

def apply_actions(json_file):
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] JSON Error: {e}")
        return

    actions = data.get('actions', [])
    print(f"[*] Processing {len(actions)} actions...")

    # FIX: Sort actions to ensure Structs are defined BEFORE they are used in function prototypes
    # Order: create_struct -> rename -> set_type -> comment
    priority = {'create_struct': 0, 'rename': 1, 'set_type': 2, 'comment': 3}
    actions.sort(key=lambda x: priority.get(x.get('type'), 10))

    for act in actions:
        try:
            kind = act.get('type')
            if kind == 'rename':
                handle_rename(act)
            elif kind == 'comment':
                handle_comment(act)
            elif kind == 'create_struct':
                handle_struct(act)
            elif kind == 'set_type':
                handle_set_type(act)
            else:
                print(f"[?] Unknown action type: {kind}")
        except Exception as e:
            print(f"[!] Error processing action {act}: {e}")

def get_target_file(binary_path):
    abs_path = os.path.abspath(binary_path)
    base_dir = os.path.dirname(abs_path)
    base_name = os.path.basename(abs_path)
    
    candidates = [
        os.path.join(base_dir, base_name + ".i64"),
        os.path.join(base_dir, os.path.splitext(base_name)[0] + ".i64")
    ]
    
    for c in candidates:
        if os.path.exists(c):
            return c, True
            
    if os.path.exists(abs_path):
        return abs_path, False

    print(f"[!] Error: File not found: {binary_path}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Apply LLM suggested changes to IDA Database.")
    parser.add_argument("binary", help="Path to the binary or database")
    parser.add_argument("json", help="Path to the LLM-generated JSON file")
    args = parser.parse_args()

    target_path, is_existing_db = get_target_file(args.binary)
    
    if is_existing_db:
        print(f"[*] Existing Database found: {target_path}")
        if not backup_database(target_path):
            print("[!] Aborting to prevent data loss.")
            return
        run_analysis = False
    else:
        print(f"[*] No database found. Using binary: {target_path}")
        print("[*] Creating and analyzing new database...")
        run_analysis = True

    try:
        idapro.open_database(target_path, run_auto_analysis=run_analysis)
    except Exception as e:
        print(f"[!] IDA Load Error: {e}")
        return

    if run_analysis:
        print("[*] Waiting for auto-analysis (this may take a moment)...")
        ida_auto.auto_wait()

    print("[*] Database ready. Applying changes from JSON...")
    apply_actions(args.json)

    print("[*] Saving changes...")
    idapro.close_database(save=True)
    print("[*] Done.")

if __name__ == "__main__":
    main()