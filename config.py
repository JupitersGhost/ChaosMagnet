# config.py
# ChaosMagnet Configuration & Theme
import os

# --- System Settings ---
POOL_SIZE = 1024          # Bytes in the entropy pool
HISTORY_LEN = 300         # How many data points to keep for the GUI graph
KEYS_DIR = "keys"         # Where to save the audit trail

# Create keys directory if missing
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

# --- Harvester Polling Rates (Seconds) ---
RATE_SYSTEM = 0.5
RATE_TRNG   = 1.0         # Poll hardware RNG every second (don't drain it too fast)
RATE_MOUSE  = 0.0         # 0 = event driven
RATE_AUDIO  = 0.2
RATE_VIDEO  = 1.0         # Slow poll to save CPU/Battery

# --- Health Check Thresholds (NIST-style) ---
# If a single byte value repeats this many times, fail.
RCT_CUTOFF = 10
# If one byte value appears more than this % of the time in a sample, fail.
APT_CUTOFF = 0.40 

# --- Theme: Cobra Lab Stealth ---
COLOR_BG         = (15, 15, 20, 255)
COLOR_WINDOW     = (30, 35, 45, 255)
COLOR_TEXT       = (220, 220, 220, 255)
COLOR_ACCENT     = (212, 175, 55, 255)
COLOR_ACCENT_DIM = (150, 120, 30, 150)
COLOR_PLOT_LINE  = (0, 255, 200, 255)
COLOR_ERROR      = (200, 50, 50, 255)
COLOR_WARN       = (200, 150, 50, 255)