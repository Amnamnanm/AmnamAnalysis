# AmanAnalysis: Security Analysis Tool

AmanAnalysis is a GUI-based tool designed for static, runtime, and deep analysis of executables and source code to identify potentially malicious behavior. It provides a user-friendly interface to collect data, analyze logs, generate risk assessments, and offers an optional AI-powered summary feature.

## What's New

This version introduces significant upgrades, including:

*   **Deep Program Analysis:** The tool can now intelligently analyze files based on their type:
    *   **Binary Files (.exe, .dll):** Detects high entropy (a sign of packing/encryption), scans for dangerous import functions, and calculates the ImpHash.
    *   **Python Source Code (.py):** Performs security analysis using an integrated `bandit` scan to find common vulnerabilities.
*   **Enhanced AI Workflows:** The AI can now perform two distinct tasks: verifying reports against raw log data or writing a professional justification based on deep analysis findings.
*   **Log Management:** A new feature has been added to safely delete all old logs directly from the UI.
*   **Refreshed UI:** The visual theme has been updated, and new controls have been added to access advanced functionality.

## Core Features

### GUI Interface
A modern and intuitive user interface built with `customtkinter`, featuring a custom theme.

### Static Analysis
*   Select a single file (.exe, .dll, .py, etc.) or an entire folder for analysis.
*   Calculates file hashes (MD5, SHA1, SHA256).
*   Extracts PE (Portable Executable) metadata, including imported functions and ImpHash.
*   Dumps all readable strings from binary files.
*   Calculates file entropy to detect packed or encrypted data.

### Deep Program Analysis
*   **Binary Analysis:** Automatically scans for suspicious imports and high entropy.
*   **Python Source Analysis:** Utilizes the `bandit` tool to identify security issues in `.py` files.

### Runtime Monitoring
*   Monitors process creation via regular snapshots.
*   Logs filesystem events in key directories (e.g., user's home, temp folders).
*   Requires administrator privileges for full effectiveness.

### Log Analysis & Risk Assessment
*   Aggregates all logs from static and runtime analysis.
*   Scans for suspicious keywords, URLs, IP addresses, and domains.
*   Calculates a risk score (Low, Medium, High) based on keyword hits and contextual triggers tailored to the specified program type (e.g., "Game", "System utility").

### AI-Powered Summaries (Optional)
*   Integrates with GGUF-format language models (via `llama-cpp-python`).
*   **Log Verification:** Generates a detailed analysis where the AI acts as a security analyst, verifying an automated report against raw log snippets.
*   **Deep Analysis Justification:** Creates a concise, professional summary justifying the findings from a deep analysis of code or binaries.
*   **Customization:** Allows for tweaking model parameters (temperature, max tokens) and system prompts via the Advanced Settings menu.

## Requirements

### Core Dependencies
*   `customtkinter`: For the graphical user interface.
*   `pefile`: For parsing PE file headers.
*   `psutil`: For process monitoring.
*   `watchdog`: For filesystem monitoring.
*   `scipy`: For calculating entropy.

### Optional Dependencies
*   **AI Features:** `llama-cpp-python` for running local AI model analysis.
*   **Python Code Analysis:** `bandit` as an external tool.

## Installation

1.  Clone the repository or download the source code.
2.  Install the required Python packages:
    ```bash
    pip install customtkinter pefile psutil watchdog scipy
    ```
3.  For Python source code analysis, install `bandit`:
    ```bash
    pip install bandit
    ```
4.  To enable the AI features, install `llama-cpp-python`. For a basic CPU-only installation:
    ```bash
    pip install llama-cpp-python
    ```
    For hardware acceleration (NVIDIA GPU, etc.), please refer to the official `llama-cpp-python` documentation for detailed installation instructions.

## Usage

1.  **Run the main script:**
    ```bash
    python your_script_name.py
    ```
2.  **(Optional) Add AI Models:**
    *   Create an `AI/` folder in the same directory as the script.
    *   Place your pre-trained GGUF models (e.g., `mistral-7b.gguf`) inside the `AI/` folder.
    *   Click "Rescan models" in the UI to make them available in the dropdown menu.

3.  **Select a Target:**
    *   Click "Pick file" to select a single executable for analysis.
    *   Click "Pick folder" to analyze all files within a directory.

4.  **Set Program Type:**
    *   Choose the most appropriate category from the "Program type" dropdown. This helps the analysis engine apply more accurate contextual rules.

5.  **Perform Analysis:**
    *   **Static Analysis:** Click "Static analysis → log". This will inspect the target(s) without running them and save the results to `logs/static/`.
    *   **Deep Program Analysis:** Click "Deep Program Analysis". The tool will analyze the files according to their type (binary, Python script, etc.) and save a detailed report to `logs/code/`. If an AI model is selected, a summary will be automatically generated afterward.
    *   **Runtime Monitoring:**
        1.  Click "Start monitoring" to begin logging process and filesystem activity.
        2.  Run the target executable (if applicable).
        3.  Click "Stop monitoring" when you are finished. Logs are saved to `logs/runtime/`.
    *   **Analyze Logs:** Click "Analyze logs". This will process all collected data from the log directories and generate a summary in `logs/findings_summary.txt`. The findings will also be displayed in the main console window.
    *   **Generate AI Summary:** After running "Analyze logs", select an AI model and click "AI Analysis". This will trigger a verification of the `findings_summary.txt` report against raw data. The results are saved to `logs/ai_analysis.txt`.

## Directory Structure

The application will create the following directories and files in its root folder:

*   **AI/:** (User-created) Place your `.gguf` language models here.
*   **logs/:** Main directory for all generated data.
    *   **static/:** Contains logs from static file analysis.
    *   **runtime/:** Contains logs from process and filesystem monitoring.
    *   **code/:** Contains detailed reports from the Deep Program Analysis.
    *   **tools/:** A place for logs from external tools (if any).
    *   **temp/:** For temporary files, such as context snippets for the AI.
*   **master\_log.txt:** A timestamped log of all actions performed within the application.
*   **findings\_summary.txt:** The detailed report generated by the "Analyze logs" action.
*   **ai\_analysis.txt:** The output from the AI summary generation.
