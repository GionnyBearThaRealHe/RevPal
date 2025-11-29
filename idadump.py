#!/usr/bin/env python3
import sys
import os
import argparse
import time

# --- Dependency Check ---
try:
    import idapro
    import ida_hexrays
    import ida_auto
    import ida_loader
    import ida_funcs
    import ida_segment
    import ida_bytes
    import ida_ida
    import idc
    import idautils
    import ida_name
    import ida_lines
    import ida_nalt
    import ida_entry
    import ida_xref
    import ida_typeinf
except ImportError as e:
    print(f"\n[!] Import Error: {e}")
    print("    1. Ensure IDA 9.0+ is installed.")
    print("    2. Ensure you have run the activation script: 'py-activate-idalib.py'")
    sys.exit(1)

# --- THE MASTER PROMPT ---
MASTER_PROMPT_TEXT = """You are an expert CTF (Capture The Flag) player specializing in Reverse Engineering and Binary Exploitation. I am going to provide you with:
1. A **Challenge Description** (Optional).
2. An **IDA Pro Dump**: This contains the memory layout, security mitigations, imports, global data, and decompiled functions of the target binary.

Your task is to analyze this data and produce two specific files: `report.md` and `solve.py`.

### PART 1: report.md
Create a Markdown file with the following three distinct sections:

**1. High-Level Analysis (The "Blue Team" View)**
* Walk through the binary's execution flow function by function (focusing on `main` and user-interaction functions).
* Explain what the program *intends* to do with user input (e.g., "It takes a username, hashes it using MD5, and compares it to a stored global").
* **Do not** mention vulnerabilities in this section. Describe the logic as if you were the developer documentation.

**2. Vulnerability Analysis (The "Red Team" View)**
* Identify specific security flaws (Stack Buffer Overflow, Format String, Heap corruption, Logic errors, Integer overflow, weak crypto, etc.).
* Cite the specific function name and variable (or line of logic) where the flaw occurs.
* Explain *why* it is vulnerable based on the provided dump (e.g., "The `read` at `sub_40120` reads 0x100 bytes into a 0x50 byte buffer").

**3. Exploit Strategy**
* Describe **in plain English** (no code) how you intend to capture the flag.
* If this is a Pwn challenge: Explain the chain (e.g., "I will leak the canary, then calculating the base address, then overwrite the RET pointer to jump to `win()`").
* If this is a Rev challenge: Explain the logic solver (e.g., "I will use z3 to constrain the input characters to match the equation checks in `check_flag`").

---

### PART 2: solve.py
Write a complete Python script to solve the challenge based on your strategy.

**Rules for the Script:**
* **Tool Selection:**
    * If the Challenge Description implies a remote server or local exploitation (shell/RCE), use `pwntools`.
    * If the challenge is about reversing an algorithm (keygen/password check), use `z3` (theorem prover) or standard Python math.
* **Placeholders:** You are analyzing a static dump. If you need a value that is dynamic (like a remote server IP) or a memory address that was not included in the text dump, you **MUST** use a placeholder variable (e.g., `HOST = "TODO_ENTER_IP"`, `GADGET_ADDR = 0xDEADBEEF # TODO: Verify gadget offset`).
* **Comments:** Add comments linking back to your `report.md` (e.g., `# Triggering the overflow described in Section 2`).
* **Robustness:** Include standard boilerplate (`p = process('./binary')` or `remote()`).

---

### PART 3: Missing Information
At the very end of your response, answer this:
* "Is there any specific memory segment, struct definition, or function assembly that is missing from this dump that prevents you from guaranteeing a solution?"

---
"""

def get_target_file(binary_path):
    """Resolves target binary or database."""
    abs_path = os.path.abspath(binary_path)
    if not os.path.exists(abs_path):
        print(f"[!] Error: File not found: {binary_path}")
        sys.exit(1)

    base_dir = os.path.dirname(abs_path)
    base_name = os.path.basename(abs_path)
    
    candidates = [
        os.path.join(base_dir, base_name + ".i64"),
        os.path.join(base_dir, os.path.splitext(base_name)[0] + ".i64"),
        os.path.join(base_dir, base_name + ".idb"),
        os.path.join(base_dir, os.path.splitext(base_name)[0] + ".idb")
    ]

    for c in candidates:
        if os.path.exists(c):
            return c, True

    return abs_path, False

def get_ptr_size():
    return 8 if ida_ida.inf_get_app_bitness() == 64 else 4

# --- Analysis Helpers ---

def get_mitigations():
    """Performs a basic checksec-style analysis."""
    results = []
    
    # 1. Canary Check
    canary_found = False
    canary_symbols = {"__stack_chk_fail", "__security_check_cookie", "__stack_smash_handler"}
    def imp_cb(ea, name, ordinal):
        nonlocal canary_found
        if name and name in canary_symbols:
            canary_found = True
            return False
        return True
        
    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, imp_cb)
        if canary_found: break
    results.append(f"Canary: {'Enabled' if canary_found else 'No'}")

    # 2. Header Checks (PIE/NX)
    base = ida_ida.inf_get_min_ea()
    header_bytes = ida_bytes.get_bytes(base, 64) or b""
    
    if header_bytes.startswith(b"\x7fELF"):
        nx_enabled = True
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if (seg.type == ida_segment.SEG_DATA or seg.type == ida_segment.SEG_BSS) and (seg.perm & ida_segment.SEGPERM_EXEC):
                nx_enabled = False
                break
        results.append(f"NX: {'Enabled' if nx_enabled else 'Disabled (Data Segments Executable!)'}")
        
        try:
            e_type = header_bytes[16]
            if e_type == 3: results.append("PIE: Enabled (ET_DYN)")
            elif e_type == 2: results.append("PIE: No (ET_EXEC)")
            else: results.append("PIE: Unknown")
        except: results.append("PIE: Check Failed")
    elif header_bytes.startswith(b"MZ"):
        results.append("Format: PE")
        if ida_ida.inf_get_filetype() == ida_ida.f_PE:
             results.append("PIE: Check ASLR flags")
    else:
        results.append("Format: Unknown")

    return " | ".join(results)

def dump_segments(f):
    f.write("\n" + "="*40 + "\n=== MEMORY LAYOUT (SEGMENTS) ===\n" + "="*40 + "\n")
    f.write(f"{'Name':<20} {'Start':<12} {'End':<12} {'Perms':<6} {'Type'}\n")
    f.write("-" * 65 + "\n")
    
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        perm_str = ""
        perm_str += "R" if seg.perm & ida_segment.SEGPERM_READ else "-"
        perm_str += "W" if seg.perm & ida_segment.SEGPERM_WRITE else "-"
        perm_str += "X" if seg.perm & ida_segment.SEGPERM_EXEC else "-"
        
        seg_type = "CODE" if seg.type == ida_segment.SEG_CODE else \
                   "DATA" if seg.type == ida_segment.SEG_DATA else \
                   "BSS " if seg.type == ida_segment.SEG_BSS else "UNK "
        
        f.write(f"{ida_segment.get_segm_name(seg):<20} {hex(seg.start_ea):<12} {hex(seg.end_ea):<12} {perm_str:<6} {seg_type}\n")

def dump_imports(f):
    f.write("\n" + "="*40 + "\n=== IMPORTS ===\n" + "="*40 + "\n")
    import_list = []
    def imp_cb(ea, name, ordinal):
        import_list.append((ea, name, ordinal))
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name: continue
        f.write(f"\n--- Module: {mod_name} ---\n")
        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name, ordinal in import_list:
            display_name = name if name else f"#{ordinal}"
            f.write(f"{hex(ea)}: {display_name}\n")
        import_list.clear()

def dump_exports(f):
    f.write("\n" + "="*40 + "\n=== EXPORTS ===\n" + "="*40 + "\n")
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        f.write(f"{hex(ea)}: {name} (Ordinal: {ordinal})\n")

def dump_strings(f):
    f.write("\n" + "="*40 + "\n=== STRINGS ===\n" + "="*40 + "\n")
    sc = idautils.Strings()
    for s in sc:
        content = str(s)
        if len(content) > 100: content = content[:97] + "..."
        f.write(f"{hex(s.ea)}: {content}\n")

def dump_structures(f):
    f.write("\n" + "="*40 + "\n=== STRUCTURES & LOCAL TYPES ===\n" + "="*40 + "\n")
    til = ida_typeinf.get_idati()
    if not til:
        f.write("// Error: Could not retrieve Type Information Library.\n")
        return

    qty = ida_typeinf.get_ordinal_limit(til)
    for i in range(qty):
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_numbered_type(til, i):
            if tinfo.is_udt():
                name = tinfo.get_type_name()
                if not name: name = f"type_{i}"
                try:
                    c_decl = tinfo._print(name, ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_SEMI)
                    if c_decl:
                        f.write(f"\n// Type Ordinal: {i}\n{c_decl}\n")
                except: pass

def dump_global_data(f):
    f.write("\n" + "="*40 + "\n=== GLOBAL VARIABLES & DATA ===\n" + "="*40 + "\n")
    
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg.type not in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]: continue

        f.write(f"\n--- Segment: {ida_segment.get_segm_name(seg)} ---\n")
        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            if not ida_bytes.is_data(ida_bytes.get_flags(head)): continue
            name = ida_name.get_name(head)
            if not name: continue 
            
            size = ida_bytes.get_item_size(head)
            val_str = ""
            if ida_bytes.is_strlit(ida_bytes.get_flags(head)):
                val_str = f'"{idc.get_strlit_contents(head)}"'
            elif size == 1: val_str = hex(ida_bytes.get_byte(head))
            elif size == 2: val_str = hex(ida_bytes.get_word(head))
            elif size == 4: val_str = hex(ida_bytes.get_dword(head))
            elif size == 8: val_str = hex(ida_bytes.get_qword(head))
            else: val_str = f"[Block of {size} bytes]"

            f.write(f"{hex(head)}: {name} = {val_str}\n")

def is_boilerplate(func_name, seg_name):
    if seg_name in [".plt", ".plt.got", ".init", ".fini"]: return True
    boilerplate_names = {"_start", "start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini"}
    if func_name in boilerplate_names: return True
    if func_name.startswith("__libc_") or func_name.startswith("_dl_"): return True
    return False

def dump_functions(f, dump_all_functions=False, include_disasm=False):
    print("Dumping functions...")
    decomp_available = ida_hexrays.init_hexrays_plugin()
    
    if not decomp_available:
        f.write("\n// [!] Hex-Rays Decompiler not available. Disassembly only.\n")

    for func_ea in idautils.Functions():
        func_obj = ida_funcs.get_func(func_ea)
        func_name = ida_funcs.get_func_name(func_ea)
        seg = ida_segment.getseg(func_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""

        if not dump_all_functions:
            if (func_obj.flags & ida_funcs.FUNC_LIB) or \
               (func_obj.flags & ida_funcs.FUNC_THUNK) or \
               (seg and seg.type == ida_segment.SEG_XTRN) or \
               is_boilerplate(func_name, seg_name):
                continue

        f.write(f"\n\n{'='*60}\nFUNCTION: {func_name} ({hex(func_ea)})\n")
        
        xrefs = []
        for xref in idautils.XrefsTo(func_ea):
            frm_name = ida_funcs.get_func_name(xref.frm)
            if not frm_name: frm_name = f"loc_{xref.frm:x}"
            xrefs.append(f"{hex(xref.frm)} ({frm_name})")
        
        if xrefs:
            f.write(f"Callers (Xrefs): {', '.join(xrefs[:10])}")
            if len(xrefs) > 10: f.write(" ...")
            f.write("\n")
            
        f.write(f"{'='*60}\n")
        
        if include_disasm:
            f.write("\n--- Disassembly ---\n")
            for head in idautils.FuncItems(func_ea):
                disasm = idc.GetDisasm(head)
                f.write(f"{hex(head)}: {disasm}\n")

        if decomp_available:
            f.write("\n--- Pseudocode ---\n")
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    for line_obj in cfunc.get_pseudocode():
                        f.write(ida_lines.tag_remove(line_obj.line) + "\n")
                else: f.write("// Decompilation failed\n")
            except Exception as e: f.write(f"// Decompilation error: {e}\n")

def main():
    parser = argparse.ArgumentParser(description="Dump IDA Pro analysis to text for LLM.")
    parser.add_argument("binary", help="Path to the binary file")
    
    parser.add_argument("--disasm", action="store_true", help="Include disassembly code")
    parser.add_argument("-p", "--prompt", action="store_true", help="Prepend Master CTF Prompt and save as .md")
    parser.add_argument("-d", "--description", help="Challenge description to insert into the prompt", type=str)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--minimal", action="store_true", help="Minimal output: No data sections, no boilerplate.")
    group.add_argument("--all", action="store_true", help="Dump EVERYTHING: All data/structs, all functions.")
    
    args = parser.parse_args()

    should_dump_data = True
    dump_all_funcs = False
    
    if args.minimal: should_dump_data = False
    elif args.all: dump_all_funcs = True

    target, is_db = get_target_file(args.binary)
    if is_db: print(f"[*] Loading Database: {target}")
    else: print(f"[*] Loading Binary: {target}")

    try: idapro.open_database(target, run_auto_analysis=True)
    except Exception as e:
        print(f"[!] Error: {e}")
        return

    print("[*] Waiting for analysis...")
    ida_auto.auto_wait()

    output_dir = os.path.dirname(target)
    # Determine extension based on Prompt flag
    ext = ".md" if args.prompt else ".txt"
    output_name = f"{os.path.basename(target)}_dump{ext}"
    output_path = os.path.join(output_dir, output_name)
    
    print(f"[*] Writing dump to: {output_path}")
    
    with open(output_path, "w", encoding="utf-8") as f:
        # 1. Write Prompt (if requested)
        if args.prompt:
            f.write(MASTER_PROMPT_TEXT)
            if args.description:
                f.write(f"**[CHALLENGE DESCRIPTION]**\n{args.description}\n\n")
            f.write("**[IDA DUMP START]**\n")
            f.write("```text\n") # Start Code Block

        # 2. Write Dump Headers
        f.write(f"Dump generated for: {os.path.basename(target)}\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        mitigations = get_mitigations()
        f.write(f"Security Mitigations: {mitigations}\n")
        
        # 3. Write Dump Body
        if should_dump_data:
            print("[*] Dumping memory layout and data sections...")
            dump_segments(f)
            dump_imports(f)
            dump_exports(f)
            dump_strings(f)
            dump_structures(f)
            dump_global_data(f)
        
        dump_functions(f, dump_all_functions=dump_all_funcs, include_disasm=args.disasm)

        # 4. Close Code Block (if prompt mode)
        if args.prompt:
            f.write("\n```\n")

    print("[*] Closing database...")
    idapro.close_database(save=False)
    print(f"[*] Success! Saved to {output_path}")

if __name__ == "__main__":
    main()