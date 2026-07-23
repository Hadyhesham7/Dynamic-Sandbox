# 🔬 Email Protection Gateway (EPG) - Layer 2: Dynamic Behavioral Sandbox

![Build Status](https://img.shields.io/badge/build-passing-success)
![Python Version](https://img.shields.io/badge/python-3.13-blue)
![Architecture](https://img.shields.io/badge/architecture-Microservice-purple)
![Platform](https://img.shields.io/badge/platform-GCP%20%7C%20Windows%20Server-orange)

## 📖 Overview
The **Dynamic Behavioral Sandbox** serves as the ultimate fail-safe layer in the Email Protection Gateway (EPG) pipeline. It is a custom-engineered, agentless detonation environment designed to analyze zero-day malware, evasive Office Macros (VBA), and polymorphic threats that successfully bypass static signature detection.

Hosted on Google Cloud Platform (GCP), this microservice detonates suspicious email attachments and URLs in a highly controlled, isolated Windows environment. By tracking sequential execution anomalies at the OS level, it identifies malicious intent before neutralizing the threat and instantly reverting the cloud infrastructure.

## 🏗️ Architecture & Core Components

This repository contains the source code for the sandbox orchestration, telemetry collection, and ML-based behavioral analysis.

### 1. Agentless Telemetry Collection (C/C++)
To prevent sandbox-aware malware from detecting the analysis environment, we utilize low-level API hooking rather than intrusive virtualization agents.
*   **MinHook Integration:** Hooks **89 critical Windows APIs** covering Cryptography (`CryptEncrypt`), Registry operations (`RegCreateKeyExA`), Network connections (`InternetOpenUrlA`), and File System modifications.
*   **JSON Execution Tracing:** Captures a chronological timeline of OS-level interactions, dumping the trace into structured JSON for the machine learning pipeline.

### 2. Behavioral Sequence Analysis (Python / PyTorch)
Located in the `/models/` directory, the AI engine processes the raw API traces.
*   **LSTM Neural Network:** A Long Short-Term Memory (LSTM) model evaluates the *sequence* of API calls rather than just their presence, detecting anomalous behavioral chains (e.g., dropping a file into `%TEMP%` followed by an outbound HTTP GET request).
*   **Performance:** Achieves **~94% accuracy** in distinguishing benign applications from obfuscated C2 beacons and ransomware.

### 3. Automated URL Analysis
*   **Playwright Engine:** Dynamically analyzes embedded email URLs using a headless browser. It tracks redirection chains, inspects DOM elements for phishing patterns, and executes obfuscated JavaScript safely.

## 📂 Repository Structure

```text
├── models/                     # LSTM model, token maps, and PyTorch dependencies
├── sandbox/                    # Core detonation logic and MacroMalware configurations
├── server_report/              # Automated report generation based on ML inferences
├── gateway_client.py           # v2.0 SDK: Webhooks, dual reporting, GCP revert API
├── pre_snapshot_cleanup.ps1    # PowerShell script to sanitize VM state before GCP snapshot
├── requirements.txt            # Python dependencies (PyInstaller, torch, playwright, etc.)
└── summary_URL_Chat.md         # Documentation on dynamic URL analysis and DOM tracking
