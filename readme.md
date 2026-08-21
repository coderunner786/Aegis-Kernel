# Aegis Runtime Defense Engine

> **Zero-Cloud, Edge-First Behavioral Anomaly Detection & Incident Forensics**  
> *Built for Smart India Hackathon (SIH) — Next-Generation Endpoint Security*

[![OS: Windows / Linux](https://img.shields.io/badge/OS-Windows%20%7C%20Linux-blue.svg)](https://github.com/coderunner786/Aegis-Kernel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Inference: Sub-1ms](https://img.shields.io/badge/Inference-%3C1ms-brightgreen.svg)]()
[![Security: Ed25519 Signed](https://img.shields.io/badge/Security-Ed25519%20Signed-orange.svg)]()

---

## Executive Summary

Traditional Antivirus platforms rely heavily on static signature databases and known file hashes, leaving endpoints exposed to **Living off the Land (LotL)** techniques and **fileless in-memory attacks** executed through legitimate system binaries (`powershell.exe`, `cmd.exe`, `wmic.exe`). Commercial Enterprise Detection and Response (EDR) solutions solve this by streaming telemetry to foreign cloud lakes, making them cost-prohibitive for small fleets and unusable in air-gapped critical infrastructure.

**Aegis** is an open-source, edge-first runtime defense engine. It extracts behavioral process telemetry and payload entropy in real time, evaluates threats locally using an asymmetric-verified Isolation Forest ML model in **sub-millisecond latency**, and logs forensic evidence to an asynchronous SQLite database.

---

## System Architecture

```text
                                    HOST ENVIRONMENT
  +----------------------------------------------------------------------------------+
  |                                                                                  |
  |   [ Process Execution ] ---> (e.g. powershell.exe -Enc JABjAGw...)                |
  |           |                                                                      |
  |           v                                                                      |
  |   +-------------------------------+                                              |
  |   | Telemetry Ingestion Layer     |  <--- WMI Win32_ProcessTrace (Windows)       |
  |   | (Parent Lineage & Context)    |  <--- /proc Lineage Scanner (Linux)          |
  |   +---------------+---------------+                                              |
  |                   |                                                              |
  |                   v                                                              |
  |   +-------------------------------+                                              |
  |   | Dynamic Feature Extraction    |  * Shannon Payload Entropy                   |
  |   | & Normalization Engine        |  * Argument Length & Token Density           |
  |   +---------------+---------------+  * System Lineage & Flag Ratios              |
  |                   |                                                              |
  |                   v                                                              |
  |   +-------------------------------+                                              |
  |   | Edge Isolation Forest Engine  |  <--- Ed25519 Cryptographic Signature Check  |
  |   | (Sub-1ms Local Inference)     |  <--- Quantized Multidimensional Baseline    |
  |   +---------------+---------------+                                              |
  |                   |                                                              |
  |         [ Anomaly Score > 75% ]                                                  |
  |                   |                                                              |
  |        +----------+-----------------------+                                      |
  |        v                                  v                                      |
  |   +-------------------------+   +------------------------------+                 |
  |   | Guarded Mitigation Hub  |   | Async Dead-Letter Queue      |                 |
  |   | * Report-Only (Default) |   | (SQLite WAL Audit Stream)    |                 |
  |   | * Rate-Limited Suspend  |   +--------------+---------------+                 |
  |   | * Auto-Rollback Window  |                  |                                 |
  |   +-------------------------+                  v                                 |
  |                                         aegis_audit.db                           |
  |                                                                                  |
  +----------------------------------------------------------------------------------+


Key Technical Innovations

100% Offline & Air-Gapped Inference: Zero cloud roundtrips. Features are scored in memory with under 1ms inference overhead.

Cryptographic Tamper Defense: The ML model (isolation_forest.pkl) is signed with an Ed25519 asymmetric key. Unsigned or modified models fail closed on boot.

Resilient Async Telemetry: SQLite logging utilizes Write-Ahead Logging (WAL) and an in-memory dead-letter buffer to prevent database locks from blocking real-time detection.

Non-Destructive Containment: When configured in enforcement mode, Aegis employs thread freezing (NtSuspendProcess) with automated cooldown rollbacks instead of destructive process termination.