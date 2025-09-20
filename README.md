AmnamAnalysis: Security Analysis Tool

![alt text](https://img.shields.io/badge/python-3.10+-blue.svg)


![alt text](https://img.shields.io/badge/license-MIT-green.svg)


AmnamAnalysis is a GUI-based tool designed for static and runtime analysis of executable files and directories to identify potentially malicious behavior. It provides a user-friendly interface to collect data, analyze logs, and generate risk assessments, with an optional AI-powered summary feature.

# Features

## Modern GUI Interface: An intuitive and clean user interface built with customtkinter.

## Static Analysis:

### Select a single file (.exe, .dll, etc.) or an entire folder for analysis.

### Calculates file hashes (MD5, SHA1, SHA256).

### Extracts PE (Portable Executable) metadata, including imported functions.

### Dumps all readable strings from binary files.

# Runtime Monitoring:

### Monitors process creation snapshots at regular intervals.

### Logs filesystem events in key directories (e.g., user's home, temp folders).

### Requires administrator privileges for full effectiveness.

# Log Analysis & Risk Assessment:

### Aggregates all logs from static and runtime analysis.

### Scans for suspicious keywords, URLs, IP addresses, and domains.

### Calculates a risk score (Low, Medium, High) based on keyword hits and contextual triggers tailored to the specified program type (e.g., "Game", "System utility").

# AI-Powered Summaries (Optional):

### Integrates with local GGUF-format language models (via llama-cpp-python).

### Generates quick or detailed summaries of the analysis findings.

### Provides customizable prompts and model parameters (temperature, max tokens).

# Easy Management:

### All logs are organized into a logs/ directory.

### Simple controls to start/stop monitoring, run analysis, and open the log folder.

# Getting Started
## Quick Start (Recommended)

### For most users, it is recommended to download the pre-compiled .exe version in the .zip archive.

Fian and download the exe_Archive.zip file.

Extract the archive.

Run AmnamAnalysis.exe. For full functionality, right-click and "Run as Administrator".

# Building from Source

## If you prefer to run the tool from the source code, you will need Python 3.x and the following libraries.

## Download the MainProgram.py:

# Install all the required libraries, such as: customtkinter, pefile, psutil, watchdog, and llama-cpp-python (optional) through the command pip install [library] in CMD after installing Python

This is an open-source project and contributions are welcome! Feel free to open an Issue to report a bug or suggest a new feature.

License

This project is licensed under the MIT License - see the LICENSE file for details.



