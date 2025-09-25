import sys
import os
import re
import io
import ctypes
import time
import queue
import hashlib
import threading
import traceback
import multiprocessing
import configparser
import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple
from scipy.stats import entropy

import customtkinter as ctk
from tkinter import filedialog, messagebox

import pefile
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

AI_BACKEND_AVAILABLE = False
try:
    from llama_cpp import Llama
    AI_BACKEND_AVAILABLE = True
except Exception:
    AI_BACKEND_AVAILABLE = False

APP_NAME = "AmanAnalysis"
LOGS_DIR = Path("logs")
STATIC_LOGS = LOGS_DIR / "static"
RUNTIME_LOGS = LOGS_DIR / "runtime"
TOOLS_LOGS = LOGS_DIR / "tools"
CODE_LOGS = LOGS_DIR / "code"
TEMP_LOGS = LOGS_DIR / "temp"
MERGED_LOG = LOGS_DIR / "master_log.txt"
FINDINGS = LOGS_DIR / "findings_summary.txt"
AI_OUT = LOGS_DIR / "ai_analysis.txt"
CONFIG_FILE = "config.ini"

PROGRAM_TYPES = ["Game", "File utility", "Network tool", "System utility", "Other"]

SUSPICIOUS_KEYWORDS = [
    "RunOnce", "AppData\\Roaming", "Temp\\", "schtasks", "reg add",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "cmd.exe /c", "powershell", "wscript", "mshta",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "SeDebugPrivilege", "AdjustTokenPrivileges", "SeTcbPrivilege", "SeImpersonatePrivilege",
    "ZwUnmapViewOfSection", "CREATE_SUSPENDED", "process hollowing",
    "sc create", "SERVICE_KERNEL_DRIVER", "driver", "lsass.exe"
]

URL_REGEX = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")

class AISettings:
    def __init__(self):
        self.temperature = 0.7
        self.max_tokens = 2048
        self.prompt_template_detailed = (
            "You are a senior security analyst acting as a final verifier. Your task is to critically evaluate a preliminary report against raw log data.\n\n"
            "INSTRUCTIONS:\n"
            "1.  **Review the Preliminary Report:** This is an automated summary that may contain false positives.\n"
            "2.  **Examine the Raw Evidence:** The 'Contextual Snippets' are your ground truth. Do they show actual malicious activity?\n"
            "3.  **Apply Your Expertise:** Use your knowledge. Official installers (like Python, Visual Studio) often have suspicious-looking strings but are benign. Is this the case here?\n"
            "4.  **Deliver Your Verdict:** State if the preliminary report was correct or misleading, provide a final verified risk level, and explain your reasoning in two concise sentences.\n\n"
            "--- PRELIMINARY REPORT ---\n{findings_text}\n\n"
            "--- RAW EVIDENCE (from full log) ---\n{snippet_text}\n\n"
            "--- YOUR VERIFIED ASSESSMENT ---\n"
            "**Verification:** The preliminary risk assessment is [Correct/Misleading].\n"
            "**Final Verified Risk Level:** [Low/Medium/High]\n"
            "**Justification:**"
        )
        self.prompt_template_deep_analysis = (
            "You are a chief security analyst writing a final report. Your team has already completed the analysis and determined the final risk level.\n"
            "Your task is to write a brief, professional justification for this decision based on the key findings provided.\n\n"
            "KEY FINDINGS:\n{findings_text}\n\n"
            "PRE-DETERMINED RISK LEVEL: **{risk_level}**\n\n"
            "--- YOUR JUSTIFICATION ---\n"
            "**Overall Risk Level:** {risk_level}\n"
            "**Justification:**"
        )

class AdvancedSettingsWindow(ctk.CTkToplevel):
    def __init__(self, master, settings_obj):
        super().__init__(master)
        self.settings = settings_obj
        self.title("Advanced AI Settings")
        self.geometry("800x600")
        self.transient(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(4, weight=1)
        
        basic_frame = ctk.CTkFrame(self)
        basic_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        basic_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(basic_frame, text="Temperature (Creativity):").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.temp_slider = ctk.CTkSlider(basic_frame, from_=0.0, to=1.0, command=self._update_temp_label)
        self.temp_slider.set(self.settings.temperature)
        self.temp_slider.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.temp_label = ctk.CTkLabel(basic_frame, text=f"{self.settings.temperature:.2f}")
        self.temp_label.grid(row=0, column=2, padx=10, pady=5)

        ctk.CTkLabel(basic_frame, text="Max Response Length (Tokens):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.max_tokens_entry = ctk.CTkEntry(basic_frame)
        self.max_tokens_entry.insert(0, str(self.settings.max_tokens))
        self.max_tokens_entry.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(self, text="Detailed Analysis Prompt Template (Logs):", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=(10, 0), sticky="w")
        self.detailed_prompt_text = ctk.CTkTextbox(self, height=150)
        self.detailed_prompt_text.insert("1.0", self.settings.prompt_template_detailed)
        self.detailed_prompt_text.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")

        ctk.CTkLabel(self, text="Deep Program Analysis Prompt Template:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=10, pady=(10, 0), sticky="w")
        self.deep_analysis_prompt_text = ctk.CTkTextbox(self, height=150)
        self.deep_analysis_prompt_text.insert("1.0", self.settings.prompt_template_deep_analysis)
        self.deep_analysis_prompt_text.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

        button_frame = ctk.CTkFrame(self)
        button_frame.grid(row=5, column=0, padx=10, pady=10, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkButton(button_frame, text="Save and Close", command=self._save_settings).grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkButton(button_frame, text="Reset to Defaults", command=self._reset_settings, fg_color="gray").grid(row=0, column=1, padx=5, pady=5)
        ctk.CTkButton(button_frame, text="Cancel", command=self.destroy, fg_color="#8B0000", hover_color="#A40000").grid(row=0, column=2, padx=5, pady=5)

    def _update_temp_label(self, value):
        self.temp_label.configure(text=f"{value:.2f}")
    
    def _save_settings(self):
        self.settings.temperature = self.temp_slider.get()
        try:
            self.settings.max_tokens = int(self.max_tokens_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Max Tokens must be a number.", parent=self)
            return
        self.settings.prompt_template_detailed = self.detailed_prompt_text.get("1.0", "end-1c")
        self.settings.prompt_template_deep_analysis = self.deep_analysis_prompt_text.get("1.0", "end-1c")
        self.destroy()

    def _reset_settings(self):
        default_settings = AISettings()
        self.settings.temperature = default_settings.temperature
        self.settings.max_tokens = default_settings.max_tokens
        self.settings.prompt_template_detailed = default_settings.prompt_template_detailed
        self.settings.prompt_template_deep_analysis = default_settings.prompt_template_deep_analysis
        
        self.temp_slider.set(self.settings.temperature)
        self.temp_label.configure(text=f"{self.settings.temperature:.2f}")
        self.max_tokens_entry.delete(0, "end")
        self.max_tokens_entry.insert(0, str(self.settings.max_tokens))
        self.detailed_prompt_text.delete("1.0", "end")
        self.detailed_prompt_text.insert("1.0", self.settings.prompt_template_detailed)
        self.deep_analysis_prompt_text.delete("1.0", "end")
        self.deep_analysis_prompt_text.insert("1.0", self.settings.prompt_template_deep_analysis)

def ensure_dirs():
    for d in [LOGS_DIR, STATIC_LOGS, RUNTIME_LOGS, TOOLS_LOGS, CODE_LOGS, TEMP_LOGS]:
        d.mkdir(parents=True, exist_ok=True)

def now_ts():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def write_text(path, text, mode="w", encoding="utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode, encoding=encoding, errors="replace") as f:
        f.write(text)

def append_master_log(text):
    write_text(MERGED_LOG, f"[{datetime.now().isoformat()}] {text}\n", mode="a")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent

def ai_dir():
    d = get_base_dir() / "AI"
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        append_master_log(f"Created AI folder: {d}")
    return d

def file_hashes(path):
    h_md5 = hashlib.md5(usedforsecurity=False)
    h_sha1 = hashlib.sha1(usedforsecurity=False)
    h_sha256 = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return (h_md5.hexdigest(), h_sha1.hexdigest(), h_sha256.hexdigest())

def extract_strings(data, min_len=6):
    results = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return [s.decode("ascii", errors="ignore") for s in results]

def pe_metadata(path):
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        lines = []
        lines.append(f"PE: {path.name}")
        lines.append(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        lines.append(f"NumberOfSections: {pe.FILE_HEADER.NumberOfSections}")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            lines.append("Imports (up to 20 per DLL):")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                funcs = ", ".join([imp.name.decode(errors="ignore") if imp.name else f"ord({imp.ordinal})" for imp in entry.imports[:20]])
                lines.append(f"  {dll}: {funcs}")
        return "\n".join(lines)
    except Exception:
        return f"[pe_metadata] Error: Could not parse {path.name}"

def dump_file_static(path, out_dir):
    lines = [f"=== File: {path} ==="]
    try:
        size = path.stat().st_size
        lines.append(f"Size: {size} bytes")
        md5, sha1, sha256 = file_hashes(path)
        lines.append(f"MD5: {md5}")
        lines.append(f"SHA1: {sha1}")
        lines.append(f"SHA256: {sha256}")
    except Exception:
        lines.append(f"Hashing error")
    if path.suffix.lower() in [".exe", ".dll", ".sys"]:
        lines.append(pe_metadata(path))
    try:
        with path.open("rb") as f:
            data = f.read()
        strs = extract_strings(data, min_len=6)
        strings_path = out_dir / f"{path.name}.strings.txt"
        write_text(strings_path, "\n".join(strs))
        lines.append(f"Strings saved: {strings_path}")
    except Exception:
        lines.append(f"Strings error")
    return "\n".join(lines) + "\n"

def walk_targets(target):
    if target.is_file():
        return [target]
    files = []
    for root, _, names in os.walk(target):
        for n in names:
            p = Path(root) / n
            if p.is_file():
                files.append(p)
    return files

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(b) for b in range(256)]
    return entropy(counts, base=2)

def get_imphash(pe):
    try:
        return pe.get_imphash()
    except AttributeError:
        return "N/A (pefile version too old or not a PE file)"
    except Exception:
        return "N/A (Error calculating)"

def analyze_binary_file(file_path: Path) -> dict:
    report = {'type': 'Binary Analysis', 'findings': []}
    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        report['findings'].append({'level': 'info', 'title': 'ImpHash', 'details': get_imphash(pe)})
        suspicious_imports = ["CreateRemoteThread", "WriteProcessMemory", "ShellExecute", "HttpSendRequest", "LoadLibrary", "GetProcAddress"]
        found_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in suspicious_imports:
                        found_imports.append(imp.name.decode())
        if found_imports:
            report['findings'].append({'level': 'medium', 'title': 'Suspicious Imports Detected', 'details': ", ".join(set(found_imports))})
        with file_path.open("rb") as f:
            data = f.read()
        ent = calculate_entropy(data)
        report['findings'].append({'level': 'info', 'title': 'File Entropy', 'details': f"{ent:.4f} / 8.0"})
        if ent > 7.2:
            report['findings'].append({'level': 'high', 'title': 'High Entropy Detected', 'details': "This is a strong indicator of packed or encrypted data, often used by malware to hide its code."})
    except pefile.PEFormatError:
        return analyze_unknown_file(file_path)
    except Exception as e:
        report['findings'].append({'level': 'error', 'title': 'Binary Analysis Failed', 'details': str(e)})
    return report

def analyze_python_source(file_path: Path) -> dict:
    report = {'type': 'Python Source Analysis (Bandit)', 'findings': []}
    command = ["bandit", "-f", "json", str(file_path)]
    try:
        process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', check=False)
        data = json.loads(process.stdout)
        results = data.get("results", [])
        if not results:
             report['findings'].append({'level': 'info', 'title': 'No issues found by Bandit', 'details': ''})
        for issue in results:
             report['findings'].append({'level': issue['issue_severity'].lower(),'title': f"[{issue['test_id']}] {issue['issue_text']}",'details': f"File: {issue['filename']}\nLine: {issue['line_number']}\nCode: {issue['code']}"})
    except (FileNotFoundError, json.JSONDecodeError, Exception) as e:
        report['findings'].append({'level': 'error', 'title': 'Bandit Analysis Failed', 'details': str(e)})
    return report

def analyze_unknown_file(file_path: Path) -> dict:
    report = {'type': 'Fallback Raw Analysis', 'findings': []}
    try:
        with file_path.open("rb") as f:
            data = f.read()
        strings = extract_strings(data)
        ent = calculate_entropy(data)
        report['findings'].append({'level': 'info', 'title': 'File Entropy', 'details': f"{ent:.4f} / 8.0"})
        if ent > 7.2:
             report['findings'].append({'level': 'medium', 'title': 'High Entropy Detected', 'details': "Could indicate compressed or encrypted data."})
        if strings:
            report['findings'].append({'level': 'info', 'title': f'Extracted {len(strings)} Strings', 'details': "\n".join(strings[:20]) + "\n..." if len(strings) > 20 else "\n".join(strings)})
        else:
            report['findings'].append({'level': 'info', 'title': 'No printable strings found', 'details': ''})
    except Exception as e:
        report['findings'].append({'level': 'error', 'title': 'Raw Analysis Failed', 'details': str(e)})
    return report

def run_deep_analysis_dispatcher(file_path: Path) -> dict:
    if file_path.suffix.lower() == '.py':
        return analyze_python_source(file_path)
    if file_path.suffix.lower() in ['.exe', '.dll', '.sys', '.ocx']:
        return analyze_binary_file(file_path)
    return analyze_unknown_file(file_path)

class FSHandler(FileSystemEventHandler):
    def __init__(self, out_path):
        self.out_path = out_path
    def on_any_event(self, event):
        line = f"{datetime.now().isoformat()} FS_EVENT type={event.event_type} path={event.src_path}"
        write_text(self.out_path, line + "\n", mode="a")

class BasicRuntimeMonitor:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.stop_event = threading.Event()
        self.thread = None
        self.fs_observer = None
        self.proc_log = out_dir / f"process_snapshot_{now_ts()}.txt"
        self.fs_log = out_dir / f"fs_events_{now_ts()}.txt"
    def start(self):
        self.fs_observer = Observer()
        handler = FSHandler(self.fs_log)
        paths = [Path.home(), Path(os.getenv("TEMP") or os.getenv("TMP") or ".")]
        for p in paths:
            try:
                self.fs_observer.schedule(handler, str(p), recursive=True)
            except Exception as e:
                append_master_log(f"[ERROR] Failed to schedule FS observer for {p}: {e}")
        try:
            self.fs_observer.start()
        except Exception as e:
            append_master_log(f"[ERROR] Failed to start FS observer: {e}")
            self.fs_observer = None
        self.thread = threading.Thread(target=self._proc_loop, daemon=True)
        self.thread.start()
    def _proc_loop(self):
        while not self.stop_event.is_set():
            lines = [f"{datetime.now().isoformat()} PROCESS_SNAPSHOT"]
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
                    info = p.info
                    exe = info.get("exe") or ""
                    cmd = " ".join(info.get("cmdline") or [])
                    lines.append(f"  pid={info.get('pid')} name={info.get('name')} exe={exe} cmd={cmd}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception as e:
                append_master_log(f"[ERROR] Failed during process iteration: {e}")
            write_text(self.proc_log, "\n".join(lines) + "\n", mode="a")
            time.sleep(5)
    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=6)
        if self.fs_observer:
            try:
                if self.fs_observer.is_alive():
                    self.fs_observer.stop()
                    self.fs_observer.join(timeout=3)
            except Exception as e:
                append_master_log(f"[ERROR] Failed to stop FS observer: {e}")

def contextual_triggers_evaluate(log_text, program_type):
    reasons = []
    extra = 0
    min_risk = ""
    elev = any(k in log_text for k in ["sedebugprivilege", "adjusttokenprivileges", "setcbprivilege", "seimpersonateprivilege"])
    inj = any(k in log_text for k in ["createremotethread", "writeprocessmemory", "virtualallocex", "process hollowing", "zwunmapviewofsection", "create_suspended"])
    autorun = any(k in log_text for k in ["runonce", "hkcu\\software\\microsoft\\windows\\currentversion\\run", "schtasks", "reg add"])
    driver = any(k in log_text for k in ["service_kernel_driver", " driver", "sc create"])
    lsass = "lsass.exe" in log_text
    sys_write = any(pat in log_text for pat in ["\\windows\\system32", "\\windows\\syswow64", "\\program files"])
    heavy_net = len(IP_REGEX.findall(log_text)) + len(URL_REGEX.findall(log_text)) > 20
    downloads_exe = re.search(r"\.(exe|dll)\b", log_text) is not None
    powershell = ("powershell" in log_text) or ("wscript" in log_text) or ("mshta" in log_text)
    if program_type == "Game":
        if elev or inj or autorun or driver or lsass or sys_write:
            extra += 10; min_risk = "High"; reasons.append("Game with privilege escalation, injection, persistence, or system modifications.")
        if heavy_net:
            extra += 2; reasons.append("Excessive networking for a game.")
    elif program_type == "File utility":
        if heavy_net: extra += 6; reasons.append("Unusual networking for a file utility.")
        if downloads_exe or powershell: extra += 6; reasons.append("Executable downloads or script chains.")
        if elev or inj: extra += 6; reasons.append("Injection or privilege escalation indicators.")
        if autorun: extra += 4; reasons.append("Persistence via autorun or scheduler.")
    elif program_type == "Network tool":
        if elev or inj or lsass: extra += 8; reasons.append("Suspicious process or memory access for a network tool.")
        if autorun: extra += 5; reasons.append("Unusual persistence.")
    elif program_type == "System utility":
        if inj or driver or lsass: extra += 4; reasons.append("Aggressive actions for a system utility.")
    else:
        if elev or inj or autorun: extra += 5; reasons.append("Privilege escalation, injection, or persistence detected.")
    if program_type != "Network tool" and (lsass and (inj or elev)):
        min_risk = "High"; reasons.append("LSASS combined with injection or privilege escalation.")
    return extra, min_risk, reasons

def analyze_logs(log_dirs: List[Path], program_type: str) -> Tuple[str, str]:
    findings, urls, ips, domains, suspicious_hits = [], set(), set(), set(), []
    process_line_regex = re.compile(r"pid=(\d+)\s+name=([^\s]+)\s+exe=([^\s]+)?\s+cmd=(.*)")
    def scan_text(text: str, source: str):
        lines = text.splitlines()
        for line in lines:
            context_pid, context_name, context_path = None, None, None
            match = process_line_regex.search(line)
            if match:
                context_pid, context_name, context_path, _ = match.groups()

            for u in URL_REGEX.findall(line): urls.add((u, context_pid, context_name, context_path))
            for i in IP_REGEX.findall(line): ips.add((i, context_pid, context_name, context_path))
            for d in DOMAIN_REGEX.findall(line): domains.add((d, context_pid, context_name, context_path))

            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in line.lower():
                    hit_details = {"keyword": kw, "source": os.path.basename(source)}
                    if match:
                        hit_details.update({"pid": context_pid, "name": context_name, "path": context_path if context_path else "N/A"})
                    if hit_details not in suspicious_hits: suspicious_hits.append(hit_details)
    
    for d in log_dirs:
        if not d.exists(): continue
        for p in Path(d).rglob('*'):
            if p.is_file() and p.suffix.lower() in [".txt", ".log", ".csv"]:
                try:
                    with p.open("r", encoding="utf-8", errors="ignore") as f:
                        scan_text(f.read(), str(p))
                except Exception as e: append_master_log(f"[ERROR] Could not read log file {p}: {e}")
    
    merged_text_for_triggers = ""
    if FINDINGS.exists():
        try:
            merged_text_for_triggers = FINDINGS.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass

    base_score = min(20, len(suspicious_hits))
    if program_type not in ["Network tool", "Game"]: base_score += min(10, max(0, len(ips) - 2))
    extra_score, min_risk, reasons = contextual_triggers_evaluate(merged_text_for_triggers.lower(), program_type)
    score = base_score + extra_score
    risk_level = "High" if score >= 15 else "Medium" if score >= 7 else "Low"
    if min_risk == "High": risk_level = "High"

    findings.append(f"Program type: {program_type}"); findings.append(f"Estimated risk: {risk_level} (score={score}, base={base_score}, extra={extra_score})")
    if reasons:
        findings.append("Contextual triggers:"); findings.extend([f"  - {r}" for r in reasons])
    
    findings.append(f"Indicators:")
    findings.append(f"  URLs: {len(urls)}"); findings.append(f"  IPs: {len(ips)}"); findings.append(f"  Domains: {len(domains)}")
    
    if suspicious_hits:
        findings.append(f"\nSuspicious keywords hits ({len(suspicious_hits)} total):")
        for hit in suspicious_hits:
            if "pid" in hit:
                findings.append(f"  - Keyword: '{hit['keyword']}', Process: {hit['name']} (PID: {hit['pid']}), Path: {hit['path']}")
            elif hit.get("keyword"):
                findings.append(f"  - Keyword: '{hit['keyword']}' found in: {hit['source']}")
            else:
                findings.append("  - Unknown keyword hit")

    format_indicator_list("URLs", urls, findings)
    format_indicator_list("IPs", ips, findings)
    format_indicator_list("Domains", domains, findings)

    result = "\n".join(findings) + "\n"; write_text(FINDINGS, result); append_master_log("Log analysis completed.")
    return result, ""

def format_indicator_list(name, indicator_set, findings):
    if not indicator_set:
        return
    clean_set = [x for x in indicator_set if len(x) == 4]
    findings.append(f"\nFound {name} ({len(clean_set)} total):")
    for item, pid, proc_name, path in sorted(
        clean_set,
        key=lambda x: (x[0] or "", x[1] or "", x[2] or "", x[3] or "")
    ):
        item = item or "<unknown>"
        proc_name = proc_name or "N/A"
        if pid:
            findings.append(f"  - {item} (in process: {proc_name}, PID: {pid})")
        else:
            findings.append(f"  - {item}")

def list_models() -> List[str]:
    try:
        return [f.name for f in ai_dir().glob("*.gguf")]
    except Exception:
        return []

def _build_context_snippets_to_temp(findings_text: str, max_items: int = 10, ctx_before: int = 2, ctx_after: int = 3) -> Path:
    ensure_dirs()
    indicators = []
    indicators.extend(re.findall(r"^\s*\d+\.\s(.+)", findings_text, re.MULTILINE))
    indicators.extend(re.findall(r"^\s{2}(\w+)\s->", findings_text, re.MULTILINE))
    seen = set()
    picked = []
    for it in indicators:
        it = it.strip()
        if not it or it in seen:
            continue
        seen.add(it)
        picked.append(it)
        if len(picked) >= max_items:
            break
    combined_path = TEMP_LOGS / f"snippets_{now_ts()}.txt"
    try:
        if MERGED_LOG.exists():
            with MERGED_LOG.open("r", encoding="utf-8", errors="ignore") as src, \
                 combined_path.open("w", encoding="utf-8", errors="replace") as out:
                lines = src.readlines()
                for indicator in picked:
                    for i, line in enumerate(lines):
                        if indicator in line:
                            start = max(0, i - ctx_before)
                            end = min(len(lines), i + ctx_after)
                            out.write(f"--- Context for '{indicator}' ---\n")
                            out.write("".join(lines[start:end]))
                            out.write("\n\n")
                            break
        else:
            with combined_path.open("w", encoding="utf-8", errors="replace") as out:
                out.write("Master log not found; no raw context available.\n")
    except Exception as e:
        append_master_log(f"[ERROR] Failed to build contextual snippets: {e}")
        with combined_path.open("w", encoding="utf-8", errors="replace") as out:
            out.write("Failed to build contextual snippets.\n")
    return combined_path

def run_ai_analysis_unified(model_name: str, findings_text: str, detailed: bool, ai_settings: AISettings) -> str:
    if not AI_BACKEND_AVAILABLE:
        return "[AI] Error: llama-cpp-python backend is not available."
    model_path = ai_dir() / model_name
    if not model_path.exists():
        return f"[AI] Error: Model file not found at: {model_path}"
    append_master_log(f"Starting AI summary (Detailed={detailed}) with model: {model_name}")
    try:
        llm = Llama(model_path=str(model_path), n_ctx=4096, n_gpu_layers=-1, verbose=False)
        if not detailed:
            prompt = ai_settings.prompt_template_deep_analysis.format(findings_text=findings_text[:4000], risk_level="")
        else:
            snippets_path = _build_context_snippets_to_temp(findings_text=findings_text, max_items=10, ctx_before=2, ctx_after=3)
            try:
                snippet_text = snippets_path.read_text(encoding="utf-8", errors="ignore")[:4000]
            except Exception:
                snippet_text = "No contextual snippets available."
            prompt = ai_settings.prompt_template_detailed.format(findings_text=findings_text[:2000], snippet_text=snippet_text)
        response = llm.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            temperature=ai_settings.temperature,
            max_tokens=ai_settings.max_tokens,
            stop=["\n\n"]
        )
        response_text = response['choices'][0]['message']['content'].strip()
        if not response_text:
            return "[AI] Error: The model returned an empty response."
        return response_text
    except Exception as e:
        full_trace = traceback.format_exc()
        append_master_log(f"[AI] CRITICAL ERROR during AI analysis: {e}\n{full_trace}")
        return f"[AI] CRITICAL ERROR: {e}"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.THEME = { "bg_color": ["#24272E", "#24272E"], "control_panel_bg": "#2B2E3A", "action_bar_bg": "#1F2128", "accent_color": "#00A2FF", "accent_hover": "#008ED9", "special_color": "#9A00FF", "special_hover": "#7F00D9", "danger_color": "#C70039", "danger_hover": "#A3002E", "text_color": "#D3D3D3" }
        self.configure(fg_color=self.THEME["bg_color"])
        self.ai_settings = AISettings()
        self.advanced_window = None
        ensure_dirs()
        ctk.set_appearance_mode("dark")
        self.title(APP_NAME)
        self.geometry("1400x850")
        self.minsize(1200, 700)
        self.selected_target: Optional[Path] = None
        self.program_type_var = ctk.StringVar(value="Other")
        self.model_choice_var = ctk.StringVar(value="")
        self.monitor: Optional[BasicRuntimeMonitor] = None
        self._log_queue = queue.Queue()
        self.grid_columnconfigure(2, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_ui()
        self.after(100, self._flush_logs)
        append_master_log(f"=== Session start :: Admin={is_admin()} :: AIBackend={AI_BACKEND_AVAILABLE} ===")

    def _build_ui(self):
        self.action_bar = ctk.CTkFrame(self, width=150, corner_radius=0, fg_color=self.THEME["action_bar_bg"])
        self.action_bar.grid(row=0, column=0, sticky="nsw")
        ctk.CTkLabel(self.action_bar, text=APP_NAME, font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20, padx=20)
        ctk.CTkButton(self.action_bar, text="Open Logs", corner_radius=6, command=lambda: self._open_path(LOGS_DIR), fg_color=self.THEME["accent_color"], hover_color=self.THEME["accent_hover"]).pack(pady=10, padx=10, fill="x")
        ctk.CTkButton(self.action_bar, text="Settings", corner_radius=6, command=self._open_advanced_settings, fg_color="gray").pack(pady=10, padx=10, fill="x")
        self.delete_logs_button = ctk.CTkButton(self.action_bar, text="Delete Old Logs", corner_radius=6, command=self._delete_old_logs, fg_color=self.THEME["danger_color"], hover_color=self.THEME["danger_hover"])
        self.delete_logs_button.pack(side="bottom", pady=20, padx=10, fill="x")

        self.control_panel = ctk.CTkFrame(self, width=350, corner_radius=0, fg_color=self.THEME["control_panel_bg"])
        self.control_panel.grid(row=0, column=1, sticky="nswe", padx=(2,0))
        target_frame = ctk.CTkFrame(self.control_panel, corner_radius=6, fg_color=self.THEME["bg_color"][0])
        target_frame.pack(pady=20, padx=20, fill="x")
        ctk.CTkLabel(target_frame, text="Target", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(10,5))
        self.target_label = ctk.CTkLabel(target_frame, text="No target selected", wraplength=300, justify="center")
        self.target_label.pack(pady=(5, 10))
        btn_row = ctk.CTkFrame(target_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=10, pady=(0,10))
        ctk.CTkButton(btn_row, text="Pick File", corner_radius=6, fg_color=self.THEME["accent_color"], hover_color=self.THEME["accent_hover"], command=self._pick_file).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ctk.CTkButton(btn_row, text="Pick Folder", corner_radius=6, fg_color=self.THEME["accent_color"], hover_color=self.THEME["accent_hover"], command=self._pick_dir).pack(side="right", expand=True, fill="x", padx=(5, 0))
        
        config_frame = ctk.CTkFrame(self.control_panel, corner_radius=6, fg_color=self.THEME["bg_color"][0])
        config_frame.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(config_frame, text="Configuration", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        ctk.CTkLabel(config_frame, text="Program type").pack(pady=(5,0))
        self.program_menu = ctk.CTkOptionMenu(config_frame, values=PROGRAM_TYPES, variable=self.program_type_var, corner_radius=6, fg_color=self.THEME["accent_color"], button_color=self.THEME["accent_hover"])
        self.program_menu.pack(pady=5, fill="x", padx=10)
        ctk.CTkLabel(config_frame, text="AI model").pack(pady=(5,0))
        self.model_menu = ctk.CTkOptionMenu(config_frame, values=self._refresh_models(), variable=self.model_choice_var, corner_radius=6, fg_color=self.THEME["accent_color"], button_color=self.THEME["accent_hover"])
        self.model_menu.pack(pady=5, fill="x", padx=10)
        self.ai_status_label = ctk.CTkLabel(config_frame, text=("AI backend: OK" if AI_BACKEND_AVAILABLE else "AI backend: unavailable"), text_color=("#A0FFA0" if AI_BACKEND_AVAILABLE else "#FF9090"))
        self.ai_status_label.pack(pady=5)
        ctk.CTkButton(config_frame, text="Rescan models", corner_radius=6, command=self._update_model_menu).pack(pady=(5,10), fill="x", padx=10)
        
        actions_frame = ctk.CTkFrame(self.control_panel, corner_radius=6, fg_color=self.THEME["bg_color"][0])
        actions_frame.pack(pady=10, padx=20, fill="x")
        ctk.CTkLabel(actions_frame, text="Actions", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        self.static_button = ctk.CTkButton(actions_frame, text="Static analysis → log", corner_radius=6, command=lambda: threading.Thread(target=self._static_analyze_worker, daemon=True).start())
        self.start_monitor_button = ctk.CTkButton(actions_frame, text="Start monitoring", corner_radius=6, command=self._start_monitor)
        self.stop_monitor_button = ctk.CTkButton(actions_frame, text="Stop monitoring", corner_radius=6, command=self._stop_monitor, fg_color=self.THEME["danger_color"], hover_color=self.THEME["danger_hover"])
        self.analyze_logs_button = ctk.CTkButton(actions_frame, text="Analyze logs", corner_radius=6, command=lambda: threading.Thread(target=self._analyze_logs_worker, daemon=True).start())
        self.ai_button = ctk.CTkButton(actions_frame, text="AI Analysis", corner_radius=6, command=lambda: threading.Thread(target=self._ai_analyze_worker, daemon=True).start())
        self.deep_code_button = ctk.CTkButton(actions_frame, text="Deep Program Analysis", corner_radius=6, command=lambda: threading.Thread(target=self._deep_analyze_worker, daemon=True).start(), fg_color=self.THEME["special_color"], hover_color=self.THEME["special_hover"])
        self.static_button.pack(pady=5, fill="x", padx=10)
        self.start_monitor_button.pack(pady=5, fill="x", padx=10)
        self.stop_monitor_button.pack(pady=5, fill="x", padx=10)
        self.analyze_logs_button.pack(pady=5, fill="x", padx=10)
        self.ai_button.pack(pady=5, fill="x", padx=10)
        self.deep_code_button.pack(pady=10, fill="x", padx=10, ipady=5)
        
        self.main_display = ctk.CTkFrame(self, corner_radius=0, fg_color=self.THEME["bg_color"][0])
        self.main_display.grid(row=0, column=2, sticky="nsew", padx=10, pady=10)
        self.main_display.grid_rowconfigure(0, weight=1)
        self.main_display.grid_columnconfigure(0, weight=1)
        self.console = ctk.CTkTextbox(self.main_display, wrap="word", font=("Courier New", 12), corner_radius=6, fg_color="#2B2E3A", text_color="#E0E0E0", border_width=1, border_color="#444857")
        self.console.grid(row=0, column=0, columnspan=2, sticky="nsew")
        self.console.tag_config("search", background="#FFA500", foreground="black")
        search_frame = ctk.CTkFrame(self.main_display, fg_color="transparent")
        search_frame.grid(row=1, column=0, sticky="ew", pady=(10,0))
        search_frame.grid_columnconfigure(0, weight=1)
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search in console...", corner_radius=6)
        self.search_entry.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(search_frame, text="Find All", command=self._search_console, width=80, corner_radius=6, fg_color=self.THEME["accent_color"], hover_color=self.THEME["accent_hover"]).grid(row=0, column=1, padx=(10, 5))
        ctk.CTkButton(search_frame, text="Clear", command=lambda: self.console.delete("1.0","end"), width=80, corner_radius=6).grid(row=0, column=2)
        status_frame = ctk.CTkFrame(self.main_display)
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10,0))
        status_frame.grid_columnconfigure(1, weight=1)
        self.status = ctk.CTkLabel(status_frame, text="Ready")
        self.status.grid(row=0, column=0, padx=10)
        self.progress = ctk.CTkProgressBar(status_frame, progress_color=self.THEME["accent_color"])
        self.progress.set(0)
        self.progress.grid(row=0, column=1, sticky="ew", padx=10)

    def _log(self, msg: str):
        append_master_log(msg); self._log_queue.put(msg)

    def _flush_logs(self):
        try:
            while True:
                self.console.insert("end", self._log_queue.get_nowait() + "\n"); self.console.see("end")
        except queue.Empty: pass
        self.after(100, self._flush_logs)

    def _set_status(self, text: str, progress: float = None):
        if progress is not None:
            self.progress.set(max(0.0, min(1.0, progress)))
            self.status.configure(text=f"{text} ({(progress*100):.0f}%)")
        else: self.status.configure(text=text)
        self.update_idletasks()

    def _open_path(self, path: Path):
        try: os.startfile(str(path))
        except Exception as e: messagebox.showerror("Error", str(e))

    def _search_console(self):
        self.console.tag_remove("search", "1.0", "end")
        query = self.search_entry.get().strip()
        if not query: return
        current_pos, count = "1.0", 0
        while True:
            pos = self.console.search(query, current_pos, "end", nocase=True)
            if not pos: break
            end_pos = f"{pos}+{len(query)}c"; self.console.tag_add("search", pos, end_pos); current_pos = end_pos; count += 1
        if count == 0: messagebox.showinfo("Search", f'Phrase "{query}" not found.')

    def _refresh_models(self) -> List[str]:
        models = list_models()
        if not models: self.model_choice_var.set("")
        else:
            if self.model_choice_var.get() not in models: self.model_choice_var.set(models[0])
        return models

    def _update_model_menu(self):
        models = self._refresh_models()
        self.model_menu.configure(values=models or [""]); self._log(f"Models in AI/: {', '.join(models) if models else 'none'}")

    def _pick_file(self):
        path = filedialog.askopenfilename(title="Pick a file", filetypes=[("All files", "*.*")])
        if path: self.selected_target = Path(path); self.target_label.configure(text=f"{self.selected_target.name}"); self._log(f"File selected: {self.selected_target}")

    def _pick_dir(self):
        path = filedialog.askdirectory(title="Pick a folder")
        if path: self.selected_target = Path(path); self.target_label.configure(text=f"{self.selected_target.name}"); self._log(f"Folder selected: {self.selected_target}")

    def _static_analyze_worker(self):
        if not self.selected_target: messagebox.showwarning("Warning", "Pick a file or folder first."); return
        self._set_status("Static analysis...", 0.0); t0 = time.time(); targets = walk_targets(self.selected_target); total = len(targets)
        out_dir = STATIC_LOGS / now_ts(); out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "static_report.txt"; write_text(report_path, f"Program type: {self.program_type_var.get()}\n\n", mode="w")
        processed, buf = 0, io.StringIO()
        for i, p in enumerate(targets, 1):
            try: res = dump_file_static(p, out_dir); buf.write(res + "\n"); processed += 1
            except Exception as e: buf.write(f"[error] {p}: {e}\n")
            self._set_status(f"Static analysis {p.name}", i/total)
        write_text(report_path, buf.getvalue(), mode="a"); self._log(f"Static report: {report_path}"); self._set_status(f"Done ({processed}/{total})", 1.0)
        append_master_log(f"Static analysis done in {time.time()-t0:.1f}s")

    def _start_monitor(self):
        if self.monitor: messagebox.showinfo("Info", "Monitoring already running."); return
        session_dir = RUNTIME_LOGS / now_ts(); session_dir.mkdir(parents=True, exist_ok=True)
        write_text(session_dir / "context.txt", f"Program type: {self.program_type_var.get()}\nAdmin: {is_admin()}\n")
        self.monitor = BasicRuntimeMonitor(session_dir); self.monitor.start(); self._log(f"Monitoring started. Logs: {session_dir}"); self._set_status("Monitoring active", 0.5)

    def _stop_monitor(self):
        if not self.monitor: self._log("Monitoring is not running."); return
        self.monitor.stop(); self.monitor = None; self._set_status("Monitoring stopped", 1.0); self._log("Monitoring stopped.")

    def _analyze_logs_worker(self):
        self._set_status("Analyzing logs...", 0.0)
        result, _ = analyze_logs([STATIC_LOGS, RUNTIME_LOGS, TOOLS_LOGS, CODE_LOGS], self.program_type_var.get())
        self._log("Analysis completed. See findings_summary.txt")
        self.console.insert("end", f"\n=== Findings Summary ===\n{result}\n")
        self.console.see("end"); self._set_status("Done", 1.0)

    def _open_advanced_settings(self):
        if self.advanced_window is None or not self.advanced_window.winfo_exists():
            self.advanced_window = AdvancedSettingsWindow(self, self.ai_settings)
        else: self.advanced_window.focus()
    
    def _delete_old_logs(self):
        if LOGS_DIR.exists():
            if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete all log files? This action cannot be undone."):
                try:
                    shutil.rmtree(LOGS_DIR)
                    self._log(f"Successfully deleted log directory: {LOGS_DIR}")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete logs: {e}")
                finally:
                    ensure_dirs()
        else:
            messagebox.showinfo("Info", "Log directory does not exist. Nothing to delete.")

    def _ai_analyze_worker(self):
        model = self.model_choice_var.get().strip()
        if not model: messagebox.showwarning("AI", "No model selected."); return
        if not FINDINGS.exists(): messagebox.showerror("AI Error", "Run 'Analyze logs' first."); return
        findings_text = FINDINGS.read_text(encoding="utf-8", errors="ignore")
        self._set_status("Running AI analysis...", 0.3)
        try:
            detailed = True
            result = run_ai_analysis_unified(
                model_name=model,
                findings_text=findings_text,
                detailed=detailed,
                ai_settings=self.ai_settings
            )
            write_text(AI_OUT, result)
            self.console.insert("end", f"\n=== AI Summary (Unified) ===\n")
            self.console.insert("end", result + "\n")
            self.console.see("end")
            self._log("AI summary completed. See ai_analysis.txt")
        except Exception as e:
            self._log(f"[AI] Error: {e}")
        finally:
            self._set_status("Done", 1.0)

    def _deep_analyze_worker(self):
        if not self.selected_target: messagebox.showwarning("Warning", "Pick a file or a folder first."); return
        self.after(0, self._set_status, "Starting Deep Analysis...", 0.0)
        targets = walk_targets(self.selected_target)
        if not targets: messagebox.showwarning("Warning", "No files found."); self.after(0, self._set_status, "Ready"); return
        
        full_report_text = ""
        with io.StringIO() as buf:
            for i, file_path in enumerate(targets):
                self.after(0, self._set_status, f"Analyzing {file_path.name}", (i + 1) / len(targets))
                result = run_deep_analysis_dispatcher(file_path)
                report_str = f"--- Analysis for: {file_path} ---\nType: {result['type']}\n\n"
                for finding in result['findings']: report_str += f"[{finding['level'].upper()}] {finding['title']}\n{finding['details']}\n\n"
                buf.write(report_str)
            full_report_text = buf.getvalue()
        
        self._log(f"Deep analysis report generated, starting AI summary...")
        model_name = self.model_choice_var.get()
        if not model_name: messagebox.showwarning("AI", "No model selected. Skipping AI summary."); self.after(0, self._set_status, "Ready", 1.0); return
        self.after(0, self.console.insert, "end", "\n=== Deep Analysis AI Summary ===\n")
        
        deep_dir = CODE_LOGS / now_ts()
        deep_dir.mkdir(parents=True, exist_ok=True)
        deep_report_path = deep_dir / "deep_report.txt"

        write_text(deep_report_path, full_report_text)

        try:
            deep_findings = deep_report_path.read_text(encoding="utf-8", errors="ignore")
            result = run_ai_analysis_unified(
                model_name=model_name,
                findings_text=deep_findings,
                detailed=True,
                ai_settings=self.ai_settings
            )
            write_text(AI_OUT, result)
            self.console.insert("end", result + "\n")
            self.console.see("end")
            self._log(f"Deep AI summary completed. See ai_analysis.txt\nFull deep report saved at: {deep_report_path}")
        except Exception as e:
            self._log(f"[AI] Error: {e}")
        finally:
            self._set_status("Done", 1.0)

def main():
    if sys.platform == "win32":
        multiprocessing.freeze_support()
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
