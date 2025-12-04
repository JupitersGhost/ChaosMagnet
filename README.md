# ChaosMagnet (Rust Core)

ChaosMagnet is an entropy harvesting and post‑quantum key minting engine built around a Rust core with a Python GUI. It combines multiple noisy subsystems (host RNG, system stats, audio, video, HID) and optional hardware TRNGs into a conservatively measured entropy pool, then uses that pool to mint Kyber/Falcon key bundles with signed audit trails.

This repository is a proof‑of‑concept for multi‑source entropy aggregation and PQC‑aware key generation on commodity hardware (e.g., 2015 Dell laptops and ESP32‑S3 boards), tested on Debian Linux and Windows 11.

## Features

- Rust core (cdylib) exposed to Python via PyO3.
- Multi‑source entropy harvesting:
    - OS RNG (OsRng / DRNG).
    - System/CPU jitter and memory state.
    - Audio ADC noise.
    - Video sensor noise (camera LSBs, temporal differences).
    - HID timing (mouse movement and clicks).
- NIST‑style health checks:
    - Repetition Count Test (RCT).
    - Adaptive Proportion Test (APT).
- Conservative entropy metrics:
    - Raw Shannon entropy (bits/byte).
    - Min‑entropy (NIST SP 800‑90B style, worst‑case).
    - Collision entropy (Rényi order 2).
    - Accumulated “true” entropy estimate per source and overall pool.
- SHA‑3 (Keccak) conditioning and mixing into a 32‑byte pool.
- Post‑quantum cryptography integration:
    - Kyber512 KEM for key encapsulation.
    - Falcon512 for detached signatures.
    - JSON “PQC bundles” written to keys/ with pool snapshot, entropy estimates, and signatures.
- Network uplink:
    - Optional HTTP uplink that ships whitened payloads + raw entropy metrics to a collector (“Ayatoki” node).
- Python GUI:
    - Real‑time entropy graph (raw vs whitened).
    - Live pool hex view.
    - Per‑source metrics and logs.
    - Controls to toggle harvesters and network uplink.
    - One‑click PQC key minting.


## Project Layout

- Cargo.toml — Rust crate configuration (cdylib, PyO3, crypto deps).
- src/lib.rs — Rust ChaosEngine core:
    - Entropy harvesters, health checks, entropy calculations, mixing and PQC bundle minting.
- main.py — DearPyGUI / Python GUI frontend that talks to the Rust core.
- config.py — GUI/theme and basic runtime configuration.
- keys/ — Generated PQC bundles (JSON) and audit artifacts.
- logs/ — Runtime logs and engine messages.


## Status and Scope

- Tested on:
    - Debian Linux (Rust core + Python GUI).
    - Windows 11 (Rust core + Python GUI).
- Intended use:
    - Research, experimentation, and demonstration of multi‑source entropy and PQC key generation.
    - NOT production‑grade RNG or key management without independent review and hardening.
- Known limitations:
    - No formal SP 800‑90B validation yet.
    - Network uplink is a simple HTTP JSON client; production deployments should add TLS/mTLS and stronger endpoint auth.
    - Entropy estimates are conservative but still approximate; they should be treated as research metrics, not certification claims.


## Requirements

- Rust 1.70+ (via rustup recommended).
- Python 3.10+.
- Platform:
    - Debian‑based Linux or Windows 11 (both tested).

Python dependencies (installed via pip):

- dearpygui
- pyo3 bindings (via maturin‑built Rust cdylib as chaos_magnet_core)
- requests / reqwest bridge as needed
- Other GUI/system libs as listed in requirements.txt (if you add one).

Rust dependencies (see Cargo.toml):

- pyo3 (extension‑module).
- sha3.
- pqcrypto‑kyber, pqcrypto‑falcon, pqcrypto‑traits.
- rand.
- reqwest (blocking, json).
- sysinfo, cpal, rdev, nokhwa.
- crossbeam‑channel, parking_lot, chrono, serde, serde_json, hex.


## Building

### 1. Build the Rust core

From the project root:

- Ensure Rust toolchain is installed (https://rustup.rs/).
- Ensure Python dev headers are available (on Linux, install python3‑dev or equivalent).

Then build the Python extension using maturin:

- Create and activate a virtual environment.
- Install maturin:
    - pip install maturin
- Build and develop the extension:
    - maturin develop --release

This will build and install the chaos_magnet_core Python module into your virtual environment.

### 2. Install Python dependencies and run the GUI

1) Create a virtual environment (recommended):

- python -m venv .venv
- Windows:
    - .venv\Scripts\activate
- Linux:
    - source .venv/bin/activate

2) Install GUI/runtime dependencies (example):

- pip install dearpygui

3) Run the GUI:

- python main.py

The GUI should detect the Rust core, start the ChaosEngine, and begin plotting entropy metrics. Make sure the keys/ and logs/ directories exist or are created by the program.

## Usage Overview

- Start main.py.
- Use the checkboxes to enable/disable:
    - System/CPU, Hardware TRNG, Audio (Mic), Video (Cam), HID (Mouse).
- Watch:
    - “Current Pool Entropy” and entropy graph (raw vs whitened).
    - Logs panel for RCT/APT failures, PQC bundle mints, and uplink messages.
- To mint a PQC bundle:
    - Click “MINT KEYPAIR”.
    - A new JSON bundle will appear under keys/, containing:
        - Kyber public/secret keys (hex).
        - Falcon signature.
        - Pool snapshot and entropy estimates at mint time.


## Security Notes

- This project is a research prototype.
- Do not treat it as a certified RNG or as your sole key management infrastructure.
- Before any production use, the following are needed:
    - Independent code review and penetration testing.
    - Formal entropy source analysis per NIST SP 800‑90B.
    - Hardened network transport (TLS 1.3/mTLS, PQC‑hybrid if desired).
    - Robust operational controls around keys, logs, and audit data.


## Roadmap (Ideas)

- Add a small “Chaos node” agent suitable for deployment on multiple machines as a distributed entropy mesh.
- Implement more detailed per‑source entropy reports and exportable metrics.
- Integrate with ESP32‑S3 or other microcontrollers as external TRNG “feather nodes.”
- Explore AI‑assisted anomaly detection on health metrics and node behavior (out‑of‑band, never touching raw keys).


## License

This project is licensed under the Apache License, Version 2.0. See LICENSE.md for details.

***

LICENSE.md

Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

“License” shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.

“Licensor” shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.

“Legal Entity” shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity. For the purposes of this definition, “control” means (i) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.

“You” (or “Your”) shall mean an individual or Legal Entity exercising permissions granted by this License.

“Source” form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.

“Object” form shall mean any form resulting from mechanical transformation or translation of a Source form, including but not limited to compiled object code, generated documentation, and conversions to other media types.

“Work” shall mean the work of authorship, whether in Source or Object form, made available under the License.

“Derivative Works” shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof.

“Contribution” shall mean any work of authorship, including the original version of the Work and any modifications or additions to that Work or Derivative Works thereof, that is intentionally submitted to Licensor for inclusion in the Work by the copyright owner or by an individual or Legal Entity authorized to submit on behalf of the copyright owner.

“Contributor” shall mean Licensor and any individual or Legal Entity on behalf of whom a Contribution has been received by Licensor and subsequently incorporated within the Work.

2. Grant of Copyright License.

Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non‑exclusive, no‑charge, royalty‑free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form.

3. Grant of Patent License.

Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non‑exclusive, no‑charge, royalty‑free, irrevocable (except as stated in this section) patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work.

4. Redistribution.

You may reproduce and distribute copies of the Work or Derivative Works thereof in any medium, with or without modifications, and in Source or Object form, provided that You meet the following conditions:

- You must give any other recipients of the Work or Derivative Works a copy of this License; and
- You must cause any modified files to carry prominent notices stating that You changed the files; and
- You must retain, in the Source form of any Derivative Works that You distribute, all copyright, patent, trademark, and attribution notices from the Source form of the Work; and
- If the Work includes a NOTICE text file, You must include a readable copy of the attribution notices contained within such NOTICE file.

5. Submission of Contributions.

Unless You explicitly state otherwise, any Contribution intentionally submitted for inclusion in the Work shall be licensed as above, without any additional terms or conditions.

6. Trademarks.

This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Work.

7. Disclaimer of Warranty.

Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON‑INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

8. Limitation of Liability.

In no event and under no legal theory shall any Contributor be liable to You for damages of any kind arising out of or related to this License or the use of the Work, even if advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability.

While redistributing the Work or Derivative Works, You may choose to offer support, warranty, indemnity, or other obligations and/or rights consistent with this License. However, in accepting such obligations, You act only on Your own behalf and not on behalf of any other Contributor.

END OF TERMS AND CONDITIONS

You can optionally add a short header:

Copyright (c) 2025 [Your Name or Handle]

Licensed under the Apache License, Version 2.0 (the “License”); you may not use this file except in compliance with the License.

=======
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
keys/              — Generated PQC bundles (not tracked by Git)
logs/              — Runtime logs and metrics (not tracked by Git)
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

## License

This project is licensed under the Apache License 2.0.
See `LICENSE.md` for full terms.