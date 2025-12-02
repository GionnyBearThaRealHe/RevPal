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
MASTER_PROMPT_TEXT = """You are an expert CTF (Capture The Flag) player specializing in Reverse Engineering and Binary Exploitation. You will be provided with an XML dump of an IDA Pro database containing memory layout, security mitigations, imports, global data, structures, and decompiled functions.

Your task is to analyze this data and produce a comprehensive report (`report.md`) and a solution script (`solve.py`).

### REPORT STRUCTURE (report.md)

**Part 1: High-Level Overview**
* **Goal:** Explain what the binary does at a macro level.
* **User Input Flow:** Describe the intended flow of user input (e.g., "Input is read via `read`, passed to a parser, then hashed").
* **Constraint:** Do not go into deep detail about individual functions here; focus on the "Big Picture" logic and intended behavior.

**Part 2: Deep Function-by-Function Analysis**
* **Requirement:** You MUST provide a detailed breakdown for every significant function found in the dump.
* **Format:** Use the following specific format for each entry:
    > **FUNCTION `<name>` (`<address>`):**
    > This function takes [describe arguments, e.g., `a1` as a user struct pointer]. It performs [describe logic, e.g., RC4 encryption on `a1->password` using a global key]. It returns [describe return value].
* **Vulnerability Spotting:** Inside these descriptions, explicitly highlight any suspicious logic (e.g., "The `memcpy` at line 15 uses a user-controlled size `v4` without bounds checking").
* **Structure Recovery:** Provide a **visual description** of all structs you identify during analysis (e.g., "Struct at `v4`: Offset 0=int, Offset 8=char*"). Format these clearly so they can be manually added to IDA's Local Types window.

**Part 3: The Win Strategy**
* **If Binary Exploitation (Pwn):**
    * **In-Depth Analysis:** Detail exactly how to trigger the vulnerability.
    * **Attack Flow:** Provide both a **High-Level** description (e.g., "Leak libc -> ROP to system") and a **Low-Level** description (e.g., "Overwrite return address at offset 72 with gadget X").
    * **Assumption Check:** Explicitly state what you are assuming might be wrong (e.g., "Assuming remote server uses Ubuntu 22.04 libc").
* **If Reverse Engineering (Rev):**
    * **Solver Logic:** Explain the algorithm used to obfuscate the flag.
    * **Strategy:** Describe your ideas on how to obtain the cleartext value (e.g., "Use Z3 to solve the system of linear equations defined in `sub_40100`").

---

### SOLUTION SCRIPT (solve.py)

Write a complete, runnable Python script based on the strategy in Part 3.

* **For Pwn:** Use `pwntools`. Include boilerplate (`p = process()` or `remote()`).
* **For Rev:** Use `z3` (theorem prover) or standard Python math to implement the solver logic.
* **Placeholders:** You are working from a static dump. If a value is dynamic (remote IP) or missing (unknown gadget address), use a clear placeholder like `GADGET = 0xDEADBEEF # TODO: Verify`.
* **Comments:** Heavily comment the code, referencing the logic described in Part 3.

---

### MISSING INFO
At the end, list any specific memory segments, missing functions, or ambiguous data that prevents a guaranteed solution.
"""

# --- ACTUATOR ADDITIONS ---
ACTUATOR_PROMPT_APPEND = """
---

### PART 4: Database Improvements (Actuator JSON)
Since you have access to Disassembly, you can suggest direct improvements to the IDA Database to make it clearer for the analyst.
If you identify functions to rename, comments to add, prototypes to update, or structs to define:
1. **Generate a JSON block** at the very end of your response.
2. Strictly follow the **Actuator JSON API** documented in the `<actuator_documentation>` section below.
3. This will allow the analyst to automatically apply your reverse engineering findings to the database.
"""

ACTUATOR_DOCS = """# IDA Actuator JSON API

If you identify opportunities to improve the database (renaming functions, defining structures, commenting, or fixing function prototypes), output a JSON block at the end of your response.

**Rules:**
1. Use **Hexadecimal Strings** for addresses (e.g., "0x401000").
2. For Structs and Types, use valid **C Syntax**.
3. Do not include comments inside the JSON itself (standard JSON only).

## JSON Schema

```json
{
  "actions": [
    {
      "type": "rename",
      "address": "0x401234",
      "name": "rc4_encrypt_loop"
    },
    {
      "type": "set_type",
      "address": "0x401234",
      "definition": "int __cdecl rc4_encrypt_loop(RC4_Context* ctx, char* buffer, int len)"
    },
    {
      "type": "comment",
      "address": "0x401234",
      "content": "XORs input byte with key byte",
      "repeatable": true
    },
    {
      "type": "create_struct",
      "name": "RC4_Context",
      "definition": "struct RC4_Context { int x; int y; uint8_t sbox[256]; };"
    }
  ]
}
```

## Action Types

### 1. `rename`
Renames a function or global variable.
* `address`: The effective address (EA) from the dump.
* `name`: The new name (no spaces, use underscores).

### 2. `set_type`
Applies a C function prototype or variable type to an address. Use this to assign structs to function arguments.
* `address`: The function start address or global variable address.
* `definition`: The full C declaration. (e.g., `MyStruct* func(int a)`).

### 3. `create_struct`
Defines a C structure in the Local Types window.
* `name`: The name of the struct.
* `definition`: The full C-style struct definition string. Ensure you use standard types (`int`, `char`, `long`, `uint8_t`, etc.).

### 4. `comment`
Adds a comment to a specific instruction or function start.
* `address`: Where to place the comment.
* `content`: The text.
* `repeatable`: (Boolean) If true, the comment appears in cross-references.
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

def cdata(content):
    """Wraps content in CDATA for XML safety."""
    return f"<![CDATA[{content}]]>"

# === XML DUMPING FUNCTIONS ===

def dump_segments(f):
    f.write('  <segments>\n')
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        perm_str = ""
        perm_str += "R" if seg.perm & ida_segment.SEGPERM_READ else "-"
        perm_str += "W" if seg.perm & ida_segment.SEGPERM_WRITE else "-"
        perm_str += "X" if seg.perm & ida_segment.SEGPERM_EXEC else "-"
        
        seg_type = "CODE" if seg.type == ida_segment.SEG_CODE else \
                   "DATA" if seg.type == ida_segment.SEG_DATA else \
                   "BSS" if seg.type == ida_segment.SEG_BSS else "UNK"
        
        f.write(f'    <segment name="{ida_segment.get_segm_name(seg)}" start="{hex(seg.start_ea)}" end="{hex(seg.end_ea)}" perms="{perm_str}" type="{seg_type}" />\n')
    f.write('  </segments>\n')

def dump_imports(f):
    f.write('  <imports>\n')
    import_list = []
    def imp_cb(ea, name, ordinal):
        import_list.append((ea, name, ordinal))
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(i)
        if not mod_name: continue
        f.write(f'    <module name="{mod_name}">\n')
        ida_nalt.enum_import_names(i, imp_cb)
        for ea, name, ordinal in import_list:
            display_name = name if name else f"#{ordinal}"
            f.write(f'      <func addr="{hex(ea)}" name="{display_name}" />\n')
        f.write('    </module>\n')
        import_list.clear()
    f.write('  </imports>\n')

def dump_exports(f):
    f.write('  <exports>\n')
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        f.write(f'    <export addr="{hex(ea)}" name="{name}" ordinal="{ordinal}" />\n')
    f.write('  </exports>\n')

def dump_strings(f):
    f.write('  <strings>\n')
    sc = idautils.Strings()
    for s in sc:
        content = str(s)
        if len(content) > 100: content = content[:97] + "..."
        # Basic escaping for string content inside attribute
        safe_content = content.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
        f.write(f'    <str addr="{hex(s.ea)}" value="{safe_content}" />\n')
    f.write('  </strings>\n')

def dump_structures(f):
    f.write('  <structures>\n')
    til = ida_typeinf.get_idati()
    if til:
        qty = ida_typeinf.get_ordinal_limit(til)
        for i in range(qty):
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, i) and tinfo.is_udt():
                name = tinfo.get_type_name() or f"type_{i}"
                try:
                    c_decl = tinfo._print(name, ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_SEMI)
                    if c_decl:
                        f.write(f'    <struct name="{name}" ordinal="{i}">\n')
                        f.write(f'      <definition>{cdata(c_decl)}</definition>\n')
                        f.write('    </struct>\n')
                except: pass
    f.write('  </structures>\n')

def dump_global_data(f):
    f.write('  <global_data>\n')
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg.type not in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]: continue
        
        f.write(f'    <segment_data name="{ida_segment.get_segm_name(seg)}">\n')
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
            
            f.write(f'      <item addr="{hex(head)}" name="{name}" size="{size}">{cdata(val_str)}</item>\n')
        f.write('    </segment_data>\n')
    f.write('  </global_data>\n')

def is_boilerplate(func_name, seg_name):
    if seg_name in [".plt", ".plt.got", ".init", ".fini"]: return True
    boilerplate_names = {"_start", "start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini"}
    if func_name in boilerplate_names: return True
    if func_name.startswith("__libc_") or func_name.startswith("_dl_"): return True
    return False

def dump_functions(f, dump_all_functions=False, include_disasm=False):
    f.write('  <functions>\n')
    print("Dumping functions...")
    decomp_available = ida_hexrays.init_hexrays_plugin()

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

        f.write(f'    <function name="{func_name}" addr="{hex(func_ea)}">\n')
        
        # Callers
        xrefs = []
        for xref in idautils.XrefsTo(func_ea):
            frm_name = ida_funcs.get_func_name(xref.frm) or f"loc_{xref.frm:x}"
            xrefs.append(f"{hex(xref.frm)} ({frm_name})")
        if xrefs:
            f.write(f'      <callers>{cdata(", ".join(xrefs[:15]))}</callers>\n')

        # Disassembly
        if include_disasm:
            f.write('      <disassembly>\n')
            f.write(cdata('\n'.join([f"{hex(head)}: {idc.GetDisasm(head)}" for head in idautils.FuncItems(func_ea)])))
            f.write('\n      </disassembly>\n')

        # Pseudocode
        if decomp_available:
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    code = '\n'.join([ida_lines.tag_remove(line_obj.line) for line_obj in cfunc.get_pseudocode()])
                    f.write(f'      <pseudocode>\n{cdata(code)}\n      </pseudocode>\n')
                else:
                    f.write('      <pseudocode status="failed" />\n')
            except Exception as e:
                f.write(f'      <pseudocode status="error">{cdata(str(e))}</pseudocode>\n')
        
        f.write('    </function>\n')
    f.write('  </functions>\n')

def main():
    parser = argparse.ArgumentParser(description="Dump IDA Pro analysis to XML for LLM.")
    parser.add_argument("binary", help="Path to the binary file")
    
    parser.add_argument("--disasm", action="store_true", help="Include disassembly code")
    parser.add_argument("-p", "--prompt", action="store_true", help="Include Master CTF Prompt in the XML")
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
    output_name = f"{os.path.basename(target)}_dump.xml"
    output_path = os.path.join(output_dir, output_name)
    print(f"[*] Writing XML dump to: {output_path}")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<ctf_analysis>\n')
        f.write(f'  <metadata>\n    <filename>{os.path.basename(target)}</filename>\n    <timestamp>{time.ctime()}</timestamp>\n    <mitigations>{get_mitigations()}</mitigations>\n  </metadata>\n')
        
        # Embed prompt instructions as XML data
        if args.prompt:
            final_prompt = MASTER_PROMPT_TEXT
            
            # Conditionally add Actuator Instructions ONLY if Prompt AND Disasm are True
            if args.disasm:
                final_prompt += ACTUATOR_PROMPT_APPEND
                
            f.write(f'  <system_prompt>\n    {cdata(final_prompt)}\n  </system_prompt>\n')
            
            # Conditionally add Actuator Documentation ONLY if Prompt AND Disasm are True
            if args.disasm:
                f.write(f'  <actuator_documentation>\n    {cdata(ACTUATOR_DOCS)}\n  </actuator_documentation>\n')
        
        if args.description:
            f.write(f'  <challenge_description>\n    {cdata(args.description)}\n  </challenge_description>\n')
        
        if should_dump_data:
            print("[*] Dumping memory layout and data sections...")
            dump_segments(f)
            dump_imports(f)
            dump_exports(f)
            dump_strings(f)
            dump_structures(f)
            dump_global_data(f)
        
        dump_functions(f, dump_all_functions=dump_all_funcs, include_disasm=args.disasm)
        
        f.write('</ctf_analysis>\n')

    print("[*] Closing database...")
    idapro.close_database(save=False)
    print(f"[*] Success! Saved to {output_path}")

if __name__ == "__main__":
    main()