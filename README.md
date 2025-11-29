# **IDA Dump Tool for LLM Analysis**

A command-line utility designed to extract comprehensive analysis data from **IDA Pro 9.0+** databases. This tool generates context-rich dumps (decompilation, disassembly, memory layout, and security mitigations) formatted specifically to assist Large Language Models (LLMs) in solving CTF challenges and performing reverse engineering tasks.

## **Features**

* **Smart Analysis:** Automatically loads existing .i64 databases or analyzes raw binaries from scratch.  
* **Context-Aware Dumping:** Extracts Functions (Decompilation \+ Disassembly), Structures, Global Variables, Imports/Exports, and Strings.  
* **LLM Optimization:** Filters out compiler boilerplate and library functions to save token space.  
* **Prompt Generation:** Can generate a ready-to-use "Master Prompt" for ChatGPT/Claude, including a custom challenge description.  
* **Security Analysis:** Automated checksec-style detection for Canary, NX, and PIE.

## **Requirements**

* **IDA Pro 9.0** or later (Required for idalib support).  
* **Python 3** installed on the host system.  
* **Root/Sudo access** (Only for the initial installer script).

## **Installation**

1. Activate idalib:  
   Before using this tool, you must ensure the IDA Python library is linked to your Python installation. Run the activation script included with IDA:  
   \# Windows  
   python "C:\\Program Files\\IDA Pro 9.0\\idalib\\python\\py-activate-idalib.py"

   \# Linux / macOS  
   sudo python3 /opt/ida-9.0/idalib/python/py-activate-idalib.py

2. Install the Tool:  
   Run the provided installer to verify dependencies and create a global command:  
   chmod \+x install.sh  
   sudo ./install.sh

## **Usage**

Run the tool from any directory against a binary or database file.  
ida-dump ./target\_binary \[flags\]

### **Flags**

| Flag | Description |
| :---- | :---- |
| \-p, \--prompt | **Recommended:** Generates a .md file containing a "Master CTF Prompt" tailored for LLMs, with the dump attached as a code block. |
| \-d "\<text\>" | Inserts a challenge description into the generated prompt (requires \-p). |
| \--disasm | Includes assembly instructions alongside pseudocode (increases file size significantly). |
| \--minimal | Minimal dump: Only filtered functions (no data segments, structs, or boilerplate). |
| \--all | Raw dump: Includes EVERYTHING (library functions, thunks, standard boilerplate, etc). |

### **Examples**

1\. Standard CTF Workflow:  
Generate a markdown report ready to paste into ChatGPT, including the challenge description.  
ida-dump ./crackme \-p \-d "Find the password. The binary listens on port 1337."

*Output: crackme\_dump.md*  
2\. Quick Analysis (Text only):  
Just get the code and data in a text file.  
ida-dump ./malware.exe

*Output: malware.exe\_dump.txt*  
3\. Deep Dive:  
Include disassembly and all compiler boilerplate for thorough inspection.  
ida-dump ./kernel\_module.ko \--all \--disasm  
