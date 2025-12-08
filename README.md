<p align="center">
  <img src="chaosmagnet.png" alt="ChaosMagnet Logo" width="240">
</p>


# ChaosMagnet (Rust Core + Python GUI)

ChaosMagnet is a proof of concept entropy harvesting engine and post-quantum key generator. It combines multiple system-level noise sources, evaluates them with basic NIST-style tests, compresses them through a cryptographic extraction process, and exposes the distilled pool for metrics, experimentation, and PQC key minting.

This repository contains the Rust engine (`cdylib`) and a Python GUI that visualizes the entropy pipeline in real time.

---

## Overview

ChaosMagnet is designed to:

* Collect entropy from multiple independent subsystems.
* Apply conservative health checks and entropy estimation.
* Compress raw noise through a SHA-based extractor.
* Maintain an internal extraction pool for consistent key material.
* Generate experimental Kyber/Falcon key bundles for demonstration.
* Optionally distribute distilled entropy frames over the network (testing only).

It is **not** a production RNG or validated implementation. It is intended for research, education, and transparent inspection.

---

## Current Features

### **Entropy Harvesting**

* System and CPU jitter
* OS RNG
* Audio (microphone) noise
* Video sensor noise (camera LSB/temporal frames)
* HID timing noise (mouse movement/click intervals)
* Optional hardware TRNG polling

### **Health Checks**

Basic NIST SP 800-90B-style checks:

* Repetition Count Test (RCT)
* Adaptive Proportion Test (APT)

### **Extraction and Metrics**

* SHA-3 extraction pipeline
* Internal extraction pool (fill %, accumulated bytes, extraction ratio)
* Per-source entropy statistics:

  * Raw Shannon entropy
  * Min-entropy estimate
  * Sample counts
* Real-time graphing of raw entropy quality
* Pool hex dump display
* Runtime logs and event tracing

### **Post-Quantum Key Minting**

* Kyber512 KEM (via pqcrypto-kyber)
* Falcon512 signatures (via pqcrypto-falcon)
* JSON key bundle output with:

  * Keys (hex-encoded)
  * Pool snapshot
  * Per-source metrics
  * Health state at mint time

### **Networking (Experimental)**

* **Uplink mode**: send whitened payloads + metrics to a collector node ("Ayatoki")
* **P2P mode**: share distilled entropy frames between peers
  **Important:** P2P mode is experimental, unauthenticated, and insecure. It is provided only for LAN testing and should not be used in adversarial settings.

---

## Project Layout

```
Cargo.toml         — Rust crate configuration
src/lib.rs         — Rust ChaosEngine (harvesters, metrics, extractor, PQC, P2P)
config.py          — Runtime and GUI configuration
main.py            — Python GUI (DearPyGUI) interfacing with Rust core
keys/              — Generated PQC bundles (created on startup)
logs/              — Runtime logs and metrics (created on startup)
```

---

## Platform Support

Tested on:

* Debian-based Linux
* Windows 11

The Rust core is stable on both. The GUI is currently most reliable on Linux and still under refinement on Windows.

---

## Installation

### 1. Build the Rust library

```bash
cargo build --release
```

This produces the Python-loadable shared library in `target/release/`.

### 2. Set up the Python environment

```bash
python -m venv .venv
source .venv/bin/activate       # Linux
# .venv\Scripts\activate        # Windows
pip install dearpygui
```

Then run:

```bash
python main.py
```

---

## Usage

The GUI provides:

* Per-source enable/disable controls
* Uplink toggles and target configuration
* P2P mode enable, port selection, and peer list
* Real-time entropy graph
* Source quality breakdown
* Live extraction pool metrics
* Audit log tail
* One-click PQC bundle minting

Generated bundles are saved under `keys/`.

---

## Security Notes

ChaosMagnet is a **research prototype**, not a certified or production-grade RNG.

Before any real deployment, the following steps are required:

* Independent review of Rust and Python components
* Formal SP 800-90B entropy source analysis
* Hardened network transport (TLS/mTLS, or PQC-hybrid)
* Authentication and replay protection for P2P mode
* Operational controls for key handling and logging

Use this system only for experimentation and learning.

---

## Known Issues

The current implementation is functional but has several limitations that are planned for future refinement:

1. **Extraction pool updates may lag behind key minting**  
   Rapid PQC key generation can outpace the GUI refresh rate, causing the displayed pool fill and extraction statistics to update slightly after the fact.

2. **Performance variability on lower-end hardware**  
   Systems with limited CPU or integrated graphics may experience occasional stuttering in the GUI, especially when multiple harvesters (video, audio, HID) are active simultaneously.

3. **Limited device multiplicity**  
   ChaosMagnet currently supports only one instance of each harvester type. Adding support for multiple cameras, USB audio devices, or other external sensors is a planned upgrade.


---

## License

This project is licensed under the Apache License 2.0.
See `LICENSE.md` for full terms.
