AmanAnalysis: Security Analysis Tool

![alt text](https://img.shields.io/badge/python-3.10+-blue.svg)


![alt text](https://img.shields.io/badge/license-MIT-green.svg)


![alt text](https://img.shields.io/github/v/release/YOUR_USERNAME/AmanAnalysis)

AmanAnalysis is a GUI-based tool designed for static and runtime analysis of executable files and directories to identify potentially malicious behavior. It provides a user-friendly interface to collect data, analyze logs, and generate risk assessments, with an optional AI-powered summary feature.

![alt text](https://user-images.githubusercontent.com/26814775/164991223-f31f9c8f-162e-47e0-8260-5232b70f1561.png)

(Recommendation: Replace the image above with a GIF showing the tool in action)

Features

✨ Modern GUI Interface: An intuitive and clean user interface built with customtkinter.

🕵️‍♂️ Static Analysis:

Select a single file (.exe, .dll, etc.) or an entire folder for analysis.

Calculates file hashes (MD5, SHA1, SHA256).

Extracts PE (Portable Executable) metadata, including imported functions.

Dumps all readable strings from binary files.

🏃‍♂️ Runtime Monitoring:

Monitors process creation snapshots at regular intervals.

Logs filesystem events in key directories (e.g., user's home, temp folders).

Requires administrator privileges for full effectiveness.

📝 Log Analysis & Risk Assessment:

Aggregates all logs from static and runtime analysis.

Scans for suspicious keywords, URLs, IP addresses, and domains.

Calculates a risk score (Low, Medium, High) based on keyword hits and contextual triggers tailored to the specified program type (e.g., "Game", "System utility").

🤖 AI-Powered Summaries (Optional):

Integrates with local GGUF-format language models (via llama-cpp-python).

Generates quick or detailed summaries of the analysis findings.

Provides customizable prompts and model parameters (temperature, max tokens).

📂 Easy Management:

All logs are organized into a logs/ directory.

Simple controls to start/stop monitoring, run analysis, and open the log folder.

Getting Started
🚀 Quick Start (Recommended)

For most users, it is recommended to download the pre-compiled version from the Releases page.

Go to the latest release.

Download the AmanAnalysis-vX.X.zip file.

Extract the archive.

Run AmanAnalysis.exe. For full functionality, right-click and "Run as Administrator".

🔧 Building from Source

If you prefer to run the tool from the source code, you will need Python 3.x and the following libraries.

Clone the repository:

code
Bash
download
content_copy
expand_less

git clone https://github.com/YOUR_USERNAME/AmanAnalysis.git
cd AmanAnalysis

Install the required Python packages:

code
Bash
download
content_copy
expand_less
IGNORE_WHEN_COPYING_START
IGNORE_WHEN_COPYING_END
pip install customtkinter pefile psutil watchdog

To enable the AI features, install llama-cpp-python:

For a basic CPU-only installation:

code
Bash
download
content_copy
expand_less
IGNORE_WHEN_COPYING_START
IGNORE_WHEN_COPYING_END
pip install llama-cpp-python

For hardware acceleration (NVIDIA GPU, etc.), please refer to the official llama-cpp-python documentation for detailed instructions.

Run the main script:

code
Bash
download
content_copy
expand_less
IGNORE_WHEN_COPYING_START
IGNORE_WHEN_COPYING_END
python main.py
How to Use

(Optional) Add AI Models:

Create an AI/ folder in the same directory as the script/.exe.

Place your pre-trained .gguf models (e.g., mistral-7b.gguf) inside the AI/ folder.

Click "Rescan models" in the UI to load them.

Select a Target:

Click "Pick file" to select a single executable.

Click "Pick folder" to analyze all files within a directory.

Set Program Type:

Choose the most appropriate category from the "Program type" dropdown. This helps the analysis engine apply more accurate contextual rules.

Perform Analysis:

Static Analysis: Click "Static analysis → log". This will inspect the target(s) without running them and save the results to logs/static/.

Runtime Monitoring:

Click "Start monitoring" to begin logging.

Run the target executable you wish to analyze.

Click "Stop monitoring" when finished. Logs are saved to logs/runtime/.

Analyze Logs: Click "Analyze logs". This processes all collected data and generates a summary in logs/findings_summary.txt.

Generate AI Summary:

After running "Analyze logs", select a model from the AI dropdown.

Click "Quick AI Summary" for a brief risk assessment.

Click "Detailed AI Analysis" for a more in-depth summary.

Directory Structure

The application will create the following directories and files in its root folder:

AI/: (User-created) Place your .gguf language models here.

logs/: Main directory for all generated data.

static/: Contains logs from static file analysis.

runtime/: Contains logs from process and filesystem monitoring.

tools/: A place for logs from external tools (if any).

master_log.txt: A timestamped log of all actions performed within the application.

findings_summary.txt: The detailed report generated by the "Analyze logs" action.

ai_analysis.txt: The output from the AI summary generation.

Contributing

This is an open-source project and contributions are welcome! Feel free to open an Issue to report a bug or suggest a new feature.

License

This project is licensed under the MIT License - see the LICENSE file for details.
