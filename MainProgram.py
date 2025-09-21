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
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple

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
MERGED_LOG = LOGS_DIR / "master_log.txt"
FINDINGS = LOGS_DIR / "findings_summary.txt"
AI_OUT = LOGS_DIR / "ai_analysis.txt"

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
DOMAIN_REGEX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,15}\b", re.IGNORECASE)

class AISettings:
    def __init__(self):
        self.temperature = 0.5
        self.max_tokens = 512
        self.prompt_template_quick = (
            "Analyze the following security report summary.\n"
            "Based on the report, what is the overall risk level (Low, Medium, or High) and provide a very short, one-sentence explanation for your decision.\n\n"
            "--- REPORT ---\n{findings_text}\n\n"
            "--- YOUR ANSWER ---\n"
            "Risk Level: "
        )
        self.prompt_template_detailed = (
            "You are a security analyst. Your task is to provide a risk level based on a summary and contextual log snippets.\n"
            "First, review the main report. Then, use the contextual snippets from the full log to verify if the suspicious items are truly malicious or just benign activity.\n"
            "Provide a final risk level (Low, Medium, High) and a clear, concise explanation for your decision. Don't always trust the quick summary. Always check the main log and check if the process owner is legit.\n\n"
            "--- MAIN REPORT ---\n{findings_text}\n\n"
            "--- CONTEXTUAL SNIPPETS FROM FULL LOG ---\n{snippet_text}\n\n"
            "--- YOUR FINAL ANALYSIS ---\n"
            "Risk Level: "
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

        ctk.CTkLabel(self, text="Quick Analysis Prompt Template:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, padx=10, pady=(10, 0), sticky="w")
        self.quick_prompt_text = ctk.CTkTextbox(self, height=150)
        self.quick_prompt_text.insert("1.0", self.settings.prompt_template_quick)
        self.quick_prompt_text.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")

        ctk.CTkLabel(self, text="Detailed Analysis Prompt Template:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, padx=10, pady=(10, 0), sticky="w")
        self.detailed_prompt_text = ctk.CTkTextbox(self, height=150)
        self.detailed_prompt_text.insert("1.0", self.settings.prompt_template_detailed)
        self.detailed_prompt_text.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")

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
        self.settings.prompt_template_quick = self.quick_prompt_text.get("1.0", "end-1c")
        self.settings.prompt_template_detailed = self.detailed_prompt_text.get("1.0", "end-1c")
        self.destroy()

    def _reset_settings(self):
        default_settings = AISettings()
        self.settings.temperature = default_settings.temperature
        self.settings.max_tokens = default_settings.max_tokens
        self.settings.prompt_template_quick = default_settings.prompt_template_quick
        self.settings.prompt_template_detailed = default_settings.prompt_template_detailed
        
        self.temp_slider.set(self.settings.temperature)
        self.temp_label.configure(text=f"{self.settings.temperature:.2f}")
        self.max_tokens_entry.delete(0, "end")
        self.max_tokens_entry.insert(0, str(self.settings.max_tokens))
        self.quick_prompt_text.delete("1.0", "end")
        self.quick_prompt_text.insert("1.0", self.settings.prompt_template_quick)
        self.detailed_prompt_text.delete("1.0", "end")
        self.detailed_prompt_text.insert("1.0", self.settings.prompt_template_detailed)

def ensure_dirs():
    for d in [LOGS_DIR, STATIC_LOGS, RUNTIME_LOGS, TOOLS_LOGS]:
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
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
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
    except Exception as e:
        return f"[pe_metadata] Error: {e}"

def dump_file_static(path, out_dir):
    lines = [f"=== File: {path} ==="]
    try:
        size = path.stat().st_size
        lines.append(f"Size: {size} bytes")
        md5, sha1, sha256 = file_hashes(path)
        lines.append(f"MD5: {md5}")
        lines.append(f"SHA1: {sha1}")
        lines.append(f"SHA256: {sha256}")
    except Exception as e:
        lines.append(f"Hashing error: {e}")
    if path.suffix.lower() in [".exe", ".dll", ".sys"]:
        lines.append(pe_metadata(path))
    try:
        with path.open("rb") as f:
            data = f.read()
        strs = extract_strings(data, min_len=6)
        strings_path = out_dir / f"{path.name}.strings.txt"
        write_text(strings_path, "\n".join(strs))
        lines.append(f"Strings saved: {strings_path}")
    except Exception as e:
        lines.append(f"Strings error: {e}")
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
            extra += 10
            min_risk = "High"
            reasons.append("Game with privilege escalation, injection, persistence, or system modifications.")
        if heavy_net:
            extra += 2
            reasons.append("Excessive networking for a game.")
    elif program_type == "File utility":
        if heavy_net:
            extra += 6
            reasons.append("Unusual networking for a file utility.")
        if downloads_exe or powershell:
            extra += 6
            reasons.append("Executable downloads or script chains.")
        if elev or inj:
            extra += 6
            reasons.append("Injection or privilege escalation indicators.")
        if autorun:
            extra += 4
            reasons.append("Persistence via autorun or scheduler.")
    elif program_type == "Network tool":
        if elev or inj or lsass:
            extra += 8
            reasons.append("Suspicious process or memory access for a network tool.")
        if autorun:
            extra += 5
            reasons.append("Unusual persistence.")
    elif program_type == "System utility":
        if inj or driver or lsass:
            extra += 4
            reasons.append("Aggressive actions for a system utility.")
    else:
        if elev or inj or autorun:
            extra += 5
            reasons.append("Privilege escalation, injection, or persistence detected.")
    if program_type != "Network tool" and (lsass and (inj or elev)):
        min_risk = "High"
        reasons.append("LSASS combined with injection or privilege escalation.")
    return extra, min_risk, reasons

def analyze_logs(log_dirs: List[Path], program_type: str) -> Tuple[str, str]:
    findings = []
    urls, ips, domains = set(), set(), set()
    suspicious_hits = []
    def scan_text(text: str, source: str):
        for u in URL_REGEX.findall(text):
            urls.add(u)
        for ip in IP_REGEX.findall(text):
            ips.add(ip)
        for d in DOMAIN_REGEX.findall(text):
            domains.add(d)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in text.lower():
                suspicious_hits.append((kw, source))
    merged_texts = []
    for d in log_dirs:
        if not d.exists():
            continue
        for root, _, names in os.walk(d):
            for n in names:
                p = Path(root) / n
                if p.suffix.lower() in [".txt", ".log", ".csv"]:
                    try:
                        with p.open("r", encoding="utf-8", errors="ignore") as f:
                            t = f.read()
                            scan_text(t, str(p))
                            merged_texts.append(t)
                    except Exception as e:
                        append_master_log(f"[ERROR] Could not read log file {p}: {e}")
    merged = "\n".join(merged_texts)
    base_score = min(20, len(suspicious_hits))
    if program_type not in ["Network tool", "Game"]:
        base_score += min(10, max(0, len(ips) - 2))
    extra_score, min_risk, reasons = contextual_triggers_evaluate(merged.lower(), program_type)
    score = base_score + extra_score
    risk_level = "Low"
    if score >= 15:
        risk_level = "High"
    elif score >= 7:
        risk_level = "Medium"
    if min_risk == "Medium" and risk_level == "Low":
        risk_level = "Medium"
    if min_risk == "High":
        risk_level = "High"
    findings.append(f"Program type: {program_type}")
    findings.append(f"Estimated risk: {risk_level} (score={score}, base={base_score}, extra={extra_score})")
    if reasons:
        findings.append("Contextual triggers:")
        for r in reasons:
            findings.append(f"  - {r}")
    findings.append("Indicators:")
    findings.append(f"  URLs: {len(urls)}")
    findings.append(f"  IPs: {len(ips)}")
    findings.append(f"  Domains: {len(domains)}")
    if suspicious_hits:
        findings.append(f"Suspicious keywords hits: {len(suspicious_hits)}")
        seen = set()
        unique_lines = []
        for kw, src in suspicious_hits:
            key = (kw, src)
            if key not in seen:
                seen.add(key)
                unique_lines.append(f"  {kw} -> {src}")
            if len(unique_lines) >= 20:
                break
        findings.extend(unique_lines)
    
    if urls:
        findings.append(f"\nSample URLs (up to 20 of {len(urls)}):")
        for i, u in enumerate(sorted(list(urls))[:20], 1):
            findings.append(f"  {i}. {u}")
        if len(urls) > 20:
            findings.append("\n--- Full List of All URLs ---")
            for u in sorted(list(urls)):
                findings.append(f"- {u}")

    if ips:
        findings.append(f"\nSample IPs (up to 20 of {len(ips)}):")
        for i, ip in enumerate(sorted(list(ips))[:20], 1):
            findings.append(f"  {i}. {ip}")
        if len(ips) > 20:
            findings.append("\n--- Full List of All IPs ---")
            for ip in sorted(list(ips)):
                findings.append(f"- {ip}")

    if domains:
        findings.append(f"\nSample Domains (up to 20 of {len(domains)}):")
        for i, d in enumerate(sorted(list(domains))[:20], 1):
            findings.append(f"  {i}. {d}")
        if len(domains) > 20:
            findings.append("\n--- Full List of All Domains ---")
            for d in sorted(list(domains)):
                findings.append(f"- {d}")
    
    result = "\n".join(findings) + "\n"
    write_text(FINDINGS, result)
    append_master_log("Log analysis completed.")
    return result, merged

def list_models() -> List[str]:
    try:
        return [f.name for f in ai_dir().glob("*.gguf")]
    except Exception:
        return []

def run_ai_analysis(model_name: str, findings_text: str, full_log_text: str, detailed: bool, ai_settings: AISettings) -> str:
    if not AI_BACKEND_AVAILABLE:
        return "[AI] Error: llama-cpp-python backend is not available."
    
    model_path = ai_dir() / model_name
    if not model_path.exists():
        return f"[AI] Error: Model file not found at: {model_path}"
    
    prompt = ""
    if not detailed:
        prompt = ai_settings.prompt_template_quick.format(findings_text=findings_text[:4000])
    else:
        contextual_snippets = []
        indicators_to_check = re.findall(r"^\s*\d+\.\s(.+)", findings_text, re.MULTILINE)
        indicators_to_check.extend(re.findall(r"^\s{2}(\w+)\s->", findings_text, re.MULTILINE))
        
        log_lines = full_log_text.splitlines()
        for indicator in set(indicators_to_check[:10]): 
            for i, line in enumerate(log_lines):
                if indicator in line:
                    start = max(0, i - 2)
                    end = min(len(log_lines), i + 3)
                    contextual_snippets.append(f"--- Context for '{indicator}' ---\n" + "\n".join(log_lines[start:end]))
                    break 
        
        snippet_text = "\n\n".join(contextual_snippets[:5])
        prompt = ai_settings.prompt_template_detailed.format(findings_text=findings_text[:2000], snippet_text=snippet_text)

    append_master_log(f"Starting AI summary (Detailed: {detailed}) with model: {model_name}")

    try:
        llm = Llama(
            model_path=str(model_path),
            n_ctx=4096,
            n_gpu_layers=0,
            verbose=False
        )
        
        append_master_log("AI model loaded successfully. Generating response...")
        
        response = llm.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            temperature=ai_settings.temperature,
            max_tokens=ai_settings.max_tokens,
            stop=["\n\n"]
        )
        
        response_text = response['choices'][0]['message']['content'].strip()
        
        if not response_text:
            return "[AI] Error: The model returned an empty response."
        
        return "Risk Level: " + response_text

    except Exception as e:
        error_message = f"[AI] CRITICAL ERROR during AI analysis.\n"
        error_message += f"Model: {model_name}\nError: {str(e)}\n\n"
        error_message += "Possible causes:\n1. Incompatible model architecture.\n2. Insufficient RAM.\n3. Corrupted model file.\n4. A bug in the llama-cpp-python library.\n"
        full_trace = traceback.format_exc()
        append_master_log(error_message + "\n" + full_trace)
        return error_message

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.ai_settings = AISettings()
        self.advanced_window = None

        ensure_dirs()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title(APP_NAME)
        self.geometry("1280x800")
        self.minsize(1100, 680)
        self.selected_target: Optional[Path] = None
        self.program_type_var = ctk.StringVar(value="Other")
        self.model_choice_var = ctk.StringVar(value="")
        self.monitor: Optional[BasicRuntimeMonitor] = None
        self._log_queue = queue.Queue()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self.after(100, self._flush_logs)
        append_master_log(f"=== Session start :: Admin={is_admin()} :: AIBackend={AI_BACKEND_AVAILABLE} ===")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, corner_radius=0, width=320)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        for i in range(20):
            self.sidebar.grid_rowconfigure(i, weight=0)
        self.sidebar.grid_rowconfigure(19, weight=1)
        ctk.CTkLabel(self.sidebar, text=APP_NAME, font=ctk.CTkFont(size=18, weight="bold")).pack(padx=14, pady=(16, 6), anchor="w")
        self.target_label = ctk.CTkLabel(self.sidebar, text="Target: none", wraplength=280, justify="left")
        self.target_label.pack(padx=14, pady=(0, 8), anchor="w")
        btn_row = ctk.CTkFrame(self.sidebar)
        btn_row.pack(padx=14, pady=(0, 8), fill="x")
        ctk.CTkButton(btn_row, text="Pick file", command=self._pick_file).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ctk.CTkButton(btn_row, text="Pick folder", command=self._pick_dir).pack(side="left", expand=True, fill="x")
        ctk.CTkLabel(self.sidebar, text="Program type", font=ctk.CTkFont(weight="bold")).pack(padx=14, pady=(10, 4), anchor="w")
        self.program_menu = ctk.CTkOptionMenu(self.sidebar, values=PROGRAM_TYPES, variable=self.program_type_var)
        self.program_menu.pack(padx=14, pady=(0, 10), fill="x")
        ctk.CTkLabel(self.sidebar, text="AI model (GGUF in AI/)", font=ctk.CTkFont(weight="bold")).pack(padx=14, pady=(10, 4), anchor="w")
        self.model_menu = ctk.CTkOptionMenu(self.sidebar, values=self._refresh_models(), variable=self.model_choice_var)
        self.model_menu.pack(padx=14, pady=(0, 8), fill="x")
        self.ai_status_label = ctk.CTkLabel(self.sidebar, text=("AI backend: OK" if AI_BACKEND_AVAILABLE else "AI backend: unavailable"), text_color=("#A0FFA0" if AI_BACKEND_AVAILABLE else "#FF9090"))
        self.ai_status_label.pack(padx=14, pady=(0, 6), anchor="w")
        ctk.CTkButton(self.sidebar, text="Rescan models", command=self._update_model_menu).pack(padx=14, pady=(0, 10), fill="x")
        ctk.CTkLabel(self.sidebar, text="Actions", font=ctk.CTkFont(weight="bold")).pack(padx=14, pady=(10, 4), anchor="w")
        ctk.CTkButton(self.sidebar, text="Static analysis → log", command=self._static_analyze).pack(padx=14, pady=6, fill="x")
        ctk.CTkButton(self.sidebar, text="Start monitoring", command=self._start_monitor).pack(padx=14, pady=(12, 6), fill="x")
        ctk.CTkButton(self.sidebar, text="Stop monitoring", command=self._stop_monitor, fg_color="#8B0000", hover_color="#A40000").pack(padx=14, pady=6, fill="x")
        ctk.CTkButton(self.sidebar, text="Analyze logs", command=self._analyze_logs).pack(padx=14, pady=(12, 6), fill="x")
        ctk.CTkButton(self.sidebar, text="Quick AI Summary", command=lambda: self._ai_analyze(detailed=False)).pack(padx=14, pady=6, fill="x")
        ctk.CTkButton(self.sidebar, text="Detailed AI Analysis", command=lambda: self._ai_analyze(detailed=True), fg_color="#004C99", hover_color="#0062CC").pack(padx=14, pady=6, fill="x")
        ctk.CTkButton(self.sidebar, text="Advanced AI Settings", command=self._open_advanced_settings, fg_color="gray").pack(padx=14, pady=6, fill="x")
        ctk.CTkButton(self.sidebar, text="Open logs folder", command=lambda: self._open_path(LOGS_DIR)).pack(padx=14, pady=10, fill="x")
        self.progress = ctk.CTkProgressBar(self.sidebar)
        self.progress.set(0)
        self.progress.pack(padx=14, pady=(6, 6), fill="x")
        self.status = ctk.CTkLabel(self.sidebar, text="Ready")
        self.status.pack(padx=14, pady=(0, 14), anchor="w")

    def _build_main(self):
        frame = ctk.CTkFrame(self, corner_radius=0)
        frame.grid(row=0, column=1, sticky="nsew")
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        topbar = ctk.CTkFrame(frame)
        topbar.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 6))
        ctk.CTkLabel(topbar, text="Console and log", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        ctk.CTkButton(topbar, text="Clear", width=80, command=lambda: self.console.delete("1.0","end")).pack(side="right")
        search_area = ctk.CTkFrame(frame)
        search_area.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 10))
        search_area.grid_columnconfigure(1, weight=1)
        self.search_entry = ctk.CTkEntry(search_area, placeholder_text="Search in console...")
        self.search_entry.grid(row=0, column=1, sticky="ew")
        ctk.CTkButton(search_area, text="Find", command=self._search_console).grid(row=0, column=2, padx=(10, 0))
        self.console = ctk.CTkTextbox(frame, wrap="word")
        self.console.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 10))

    def _log(self, msg: str):
        append_master_log(msg)
        self._log_queue.put(msg)

    def _flush_logs(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                self.console.insert("end", msg + "\n")
                self.console.see("end")
        except queue.Empty:
            pass
        self.after(100, self._flush_logs)

    def _set_status(self, text: str, progress: float = None):
        self.status.configure(text=text)
        if progress is not None:
            self.progress.set(max(0.0, min(1.0, progress)))
        self.update_idletasks()

    def _open_path(self, path: Path):
        try:
            os.startfile(str(path))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _search_console(self):
        query = self.search_entry.get().strip()
        if not query:
            return
        start_pos = self.console.index("insert + 1c")
        pos = self.console.search(query, start_pos, "end", nocase=True)
        if pos:
            self.console.tag_remove("sel", "1.0", "end")
            end_pos = f"{pos}+{len(query)}c"
            self.console.tag_add("sel", pos, end_pos)
            self.console.mark_set("insert", pos)
            self.console.see(pos)
        else:
            pos = self.console.search(query, "1.0", "end", nocase=True)
            if pos:
                self.console.tag_remove("sel", "1.0", "end")
                end_pos = f"{pos}+{len(query)}c"
                self.console.tag_add("sel", pos, end_pos)
                self.console.mark_set("insert", pos)
                self.console.see(pos)
            else:
                 messagebox.showinfo("Search", f'Phrase "{query}" not found.')

    def _refresh_models(self) -> List[str]:
        models = list_models()
        if not models:
            self.model_choice_var.set("")
        else:
            if self.model_choice_var.get() not in models:
                self.model_choice_var.set(models[0])
        return models

    def _update_model_menu(self):
        models = self._refresh_models()
        self.model_menu.configure(values=models or [""])
        self._log(f"Models in AI/: {', '.join(models) if models else 'none'}")

    def _pick_file(self):
        path = filedialog.askopenfilename(title="Pick executable", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.selected_target = Path(path)
            self.target_label.configure(text=f"Target: {self.selected_target}")
            self._log(f"File selected: {self.selected_target}")

    def _pick_dir(self):
        path = filedialog.askdirectory(title="Pick folder")
        if path:
            self.selected_target = Path(path)
            self.target_label.configure(text=f"Target: {self.selected_target}")
            self._log(f"Folder selected: {self.selected_target}")

    def _static_analyze(self):
        if not self.selected_target:
            messagebox.showwarning("Warning", "Pick a file or folder first.")
            return
        def worker():
            self._set_status("Static analysis...", 0.0)
            t0 = time.time()
            targets = walk_targets(self.selected_target)
            total = len(targets)
            out_dir = STATIC_LOGS / now_ts()
            out_dir.mkdir(parents=True, exist_ok=True)
            report_path = out_dir / "static_report.txt"
            write_text(report_path, f"Program type: {self.program_type_var.get()}\n\n", mode="w")
            processed = 0
            with io.StringIO() as buf:
                for i, p in enumerate(targets, 1):
                    try:
                        res = dump_file_static(p, out_dir)
                        buf.write(res + "\n")
                        processed += 1
                    except Exception as e:
                        buf.write(f"[error] {p}: {e}\n")
                    self._set_status(f"Static analysis {i}/{total}", i/total if total else 0.0)
                write_text(report_path, buf.getvalue(), mode="a")
            self._log(f"Static report: {report_path}")
            self._set_status(f"Done ({processed}/{total})", 1.0)
            append_master_log(f"Static analysis done in {time.time()-t0:.1f}s :: type={self.program_type_var.get()}")
        threading.Thread(target=worker, daemon=True).start()

    def _start_monitor(self):
        if self.monitor:
            messagebox.showinfo("Info", "Monitoring already running.")
            return
        session_dir = RUNTIME_LOGS / now_ts()
        session_dir.mkdir(parents=True, exist_ok=True)
        write_text(session_dir / "context.txt", f"Program type: {self.program_type_var.get()}\nAdmin: {is_admin()}\n")
        self.monitor = BasicRuntimeMonitor(session_dir)
        self.monitor.start()
        self._log(f"Monitoring started. Logs: {session_dir}")
        self._set_status("Monitoring active", 0.5)

    def _stop_monitor(self):
        if not self.monitor:
            self._log("Monitoring is not running.")
            return
        self.monitor.stop()
        self.monitor = None
        self._set_status("Monitoring stopped", 1.0)
        self._log("Monitoring stopped.")

    def _analyze_logs(self):
        def worker():
            self._set_status("Analyzing logs...", 0.0)
            result, _ = analyze_logs([STATIC_LOGS, RUNTIME_LOGS, TOOLS_LOGS], self.program_type_var.get())
            self._log("Analysis completed. See findings_summary.txt")
            self.console.insert("end", "\n=== Findings (excerpt) ===\n")
            self.console.insert("end", result[:4000] + ("\n... (truncated)\n" if len(result) > 4000 else "\n"))
            self.console.see("end")
            self._set_status("Done", 1.0)
        threading.Thread(target=worker, daemon=True).start()

    def _open_advanced_settings(self):
        if self.advanced_window is None or not self.advanced_window.winfo_exists():
            self.advanced_window = AdvancedSettingsWindow(self, self.ai_settings)
        else:
            self.advanced_window.focus()

    def _ai_analyze(self, detailed: bool):
        model = self.model_choice_var.get().strip()
        if not model:
            messagebox.showwarning("AI", "No *.gguf models found in AI/ or no model selected.")
            return
        if not AI_BACKEND_AVAILABLE:
            messagebox.showerror("AI", "AI backend unavailable. Install: pip install llama-cpp-python")
            return
        if not FINDINGS.exists():
            messagebox.showerror("AI Error", "File 'findings_summary.txt' not found.\nPlease run 'Analyze logs' before requesting an AI summary.")
            return

        messagebox.showinfo(
            "AI Analysis Started",
            "The AI is now processing the logs. This may take several minutes depending on your CPU and the model size.\n\nThe application may become unresponsive during this time. Please be patient."
        )

        def worker():
            analysis_type = "Detailed" if detailed else "Quick"
            self._set_status(f"{analysis_type} AI summary...", 0.2)
            try:
                findings_text = FINDINGS.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                findings_text = "No findings could be read."
            
            full_log_text = ""
            if detailed:
                try:
                    full_log_text = MERGED_LOG.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    full_log_text = "Could not read full master log."

            ai_text = run_ai_analysis(
                model_name=model,
                findings_text=findings_text,
                full_log_text=full_log_text,
                detailed=detailed,
                ai_settings=self.ai_settings
            )
            write_text(AI_OUT, ai_text)
            self.console.insert("end", f"\n=== {analysis_type} AI Summary ===\n")
            self.console.insert("end", ai_text + "\n")
            self.console.see("end")
            self._log(f"{analysis_type} AI summary completed. See ai_analysis.txt")
            self._set_status("Done", 1.0)
        threading.Thread(target=worker, daemon=True).start()

def main():
    multiprocessing.freeze_support()
    if len(sys.argv) > 0:
        script_name = os.path.basename(sys.argv[0])
    else:
        script_name = "your_script_name.py"
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
