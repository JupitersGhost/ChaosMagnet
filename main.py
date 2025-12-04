#!/usr/bin/env python3
"""
ChaosMagnet GUI v3.3 - Cobra Lab
Full-featured entropy harvesting with Rust backend + P2P Support
"""
import dearpygui.dearpygui as dpg
import json
import chaos_magnet_core 
import config
import time

# --- Init Rust Backend ---
try:
    engine = chaos_magnet_core.ChaosEngine() 
    print("DEBUG: Rust Core Loaded & Running.")
except Exception as e:
    print(f"FATAL: Could not load Rust core: {e}")
    exit(1)

# --- Harvester Availability Detection ---
harvester_info = {
    "System/CPU": {"rust_name": "SYSTEM", "available": True},
    "Hardware/TRNG": {"rust_name": "TRNG", "available": True},
    "Audio (Mic)": {"rust_name": "AUDIO", "available": True},
    "Video (Cam)": {"rust_name": "VIDEO", "available": True},
    "HID (Mouse)": {"rust_name": "MOUSE", "available": True},
}

# --- GUI Update Throttling ---
LAST_UPDATE_TIME = 0.0
UPDATE_INTERVAL = 0.1  # 100ms = 10 FPS

# --- Helper Functions ---
def safe_float(value, default=0.0):
    """Safely convert any value to float"""
    try:
        if isinstance(value, str):
            # Handle empty strings
            if not value or value == "(?)" or value == "N/A":
                return default
            return float(value)
        elif isinstance(value, (int, float)):
            return float(value)
        else:
            return default
    except (ValueError, TypeError):
        return default

def safe_int(value, default=0):
    """Safely convert any value to int"""
    try:
        if isinstance(value, str):
            if not value or value == "(?)" or value == "N/A":
                return default
            return int(float(value))  # Handle "4.0" strings
        elif isinstance(value, (int, float)):
            return int(value)
        else:
            return default
    except (ValueError, TypeError):
        return default

# --- Callbacks ---
def toggle_harvester(sender, app_data, user_data):
    """Toggle individual harvester on/off"""
    h_name = user_data
    info = harvester_info.get(h_name)
    if info:
        engine.toggle_harvester(info["rust_name"], app_data)
        status = "Active" if app_data else "Inactive"
        print(f"GUI: {h_name} -> {status}")

def toggle_network(sender, app_data, user_data):
    """Toggle network uplink to Ayatoki"""
    engine.toggle_uplink(app_data)
    status = "ENABLED" if app_data else "DISABLED"
    print(f"GUI: Network Uplink -> {status}")

def toggle_p2p(sender, app_data, user_data):
    """Toggle P2P entropy sharing"""
    engine.toggle_p2p(app_data)
    status = "ENABLED" if app_data else "DISABLED"
    print(f"GUI: P2P Mode -> {status}")

def callback_ip_update(sender, app_data):
    """Update Target IP in Rust"""
    if app_data:
        engine.set_network_target(app_data)

def callback_p2p_port_update(sender, app_data):
    """Update P2P listen port"""
    try:
        port = int(app_data)
        if 1024 <= port <= 65535:
            engine.set_p2p_port(port)
        else:
            print(f"GUI: Invalid port {port} (must be 1024-65535)")
    except ValueError:
        print(f"GUI: Invalid port value: {app_data}")

def callback_add_peer(sender, app_data):
    """Add peer IP for P2P sharing"""
    if app_data:
        try:
            engine.add_peer(app_data)
            print(f"GUI: Added peer {app_data}")
        except Exception as e:
            print(f"GUI: Error adding peer: {e}")

def callback_mint_pqc(sender, app_data):
    """Trigger Rust to generate and save a PQC Key Bundle"""
    try:
        msg = engine.mint_pqc_bundle("GUI_USER")
        dpg.set_value("txt_last_key", f"Last: {msg}")
        print(f"GUI: {msg}")
    except Exception as e:
        dpg.set_value("txt_last_key", f"Error: {e}")
        print(f"GUI PQC Error: {e}")

def update_gui():
    """Main GUI update loop - syncs with Rust backend"""
    global LAST_UPDATE_TIME
    
    # Throttle updates to 10 FPS
    current_time = time.time()
    if current_time - LAST_UPDATE_TIME < UPDATE_INTERVAL:
        return
    LAST_UPDATE_TIME = current_time
    
    try:
        # 1. Get Data from Rust
        raw_metrics = engine.get_metrics() 
        metrics = json.loads(raw_metrics)
        
        # 2. Update Entropy Graph (use raw entropy, not whitened)
        history = metrics.get('history_raw', metrics.get('history', []))
        if history:
            dpg.set_value("series_entropy", [list(range(len(history))), history])
        
        # 3. Update Stats with safe parsing
        total_bytes = safe_int(metrics.get('total_bytes', 0))
        current_entropy = safe_float(metrics.get('current_raw_entropy', 0.0))
        
        dpg.set_value("txt_bytes", f"Bytes Harvested: {total_bytes}")
        dpg.set_value("txt_quality", f"Current Raw Entropy: {current_entropy:.4f} / 8.0")
        
        # 4. NEW: Extraction Pool Metrics
        pool_fill = safe_float(metrics.get('extraction_pool_fill', 0.0))
        pool_accum = safe_int(metrics.get('extraction_pool_accumulated', 0))
        extract_count = safe_int(metrics.get('extractions_count', 0))
        total_raw = safe_int(metrics.get('total_raw_consumed', 0))
        total_extracted = safe_int(metrics.get('total_extracted_bytes', 0))
        
        # Calculate ratio safely
        if total_extracted > 0:
            ratio = total_raw / total_extracted
        else:
            ratio = 0.0
        
        # Display extraction metrics
        dpg.set_value("txt_pool_fill", f"Pool Fill: {pool_fill:.1f}%")
        dpg.set_value("txt_pool_accum", f"Accumulated: {pool_accum} bytes")
        dpg.set_value("txt_extractions", f"Extractions: {extract_count}")
        dpg.set_value("txt_ratio", f"Compression Ratio: {ratio:.1f}:1")
        
        # 5. NEW: Source Quality Breakdown
        source_quality = metrics.get('source_quality', {})
        breakdown_text = "SOURCE QUALITY BREAKDOWN:\n"
        for source, quality in source_quality.items():
            raw_shannon = safe_float(quality.get('raw_shannon', 0.0))
            min_ent = safe_float(quality.get('min_entropy', 0.0))
            samples = safe_int(quality.get('samples', 0))
            breakdown_text += f"{source}: Shannon={raw_shannon:.3f} Min={min_ent:.3f} Samples={samples}\n"
        
        dpg.set_value("txt_source_breakdown", breakdown_text)
        
        # 6. Pool State Display
        pool_hex = metrics.get('pool_hex', '')
        dpg.set_value("txt_pool", pool_hex)
        
        # 7. Update Logs (last 15 lines)
        logs = metrics.get('logs', [])
        log_text = "\n".join(logs[-15:])
        dpg.set_value("txt_console", log_text)

        # 8. Dynamic Status Indicators
        # Network Status
        if metrics.get("net_mode", False):
            dpg.configure_item("txt_net_status", default_value="UPLINK: ONLINE (Ayatoki)", color=config.COLOR_PLOT_LINE)
        else:
            dpg.configure_item("txt_net_status", default_value="UPLINK: OFFLINE (Local Mode)", color=config.COLOR_WARN)
        
        # P2P Status
        p2p_active = metrics.get("p2p_active", False)
        p2p_peers = safe_int(metrics.get("p2p_peer_count", 0))
        p2p_received = safe_int(metrics.get("p2p_received_count", 0))
        
        if p2p_active:
            dpg.configure_item("txt_p2p_status", 
                default_value=f"P2P: ACTIVE ({p2p_peers} peers, {p2p_received} received)", 
                color=config.COLOR_PLOT_LINE)
        else:
            dpg.configure_item("txt_p2p_status", 
                default_value="P2P: OFFLINE", 
                color=config.COLOR_WARN)
             
        # PQC Status
        if metrics.get("pqc_ready", False):
            dpg.configure_item("txt_pqc_status", default_value="PQC STATUS: ACTIVE (Kyber/Falcon)", color=config.COLOR_PLOT_LINE)
        else:
            dpg.configure_item("txt_pqc_status", default_value="PQC STATUS: DISABLED", color=config.COLOR_ERROR)

    except json.JSONDecodeError as e:
        print(f"GUI Sync Error - JSON Parse: {e}")
    except Exception as e:
        print(f"GUI Sync Error: {e}")

# --- Build UI ---
dpg.create_context()

with dpg.theme() as global_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_WindowBg, config.COLOR_WINDOW)
        dpg.add_theme_color(dpg.mvThemeCol_Text, config.COLOR_TEXT)
        dpg.add_theme_color(dpg.mvThemeCol_PlotLines, config.COLOR_PLOT_LINE)
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, config.COLOR_BG)
        dpg.add_theme_color(dpg.mvThemeCol_Button, config.COLOR_BG)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, config.COLOR_ACCENT_DIM)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, config.COLOR_ACCENT)
        dpg.add_theme_color(dpg.mvThemeCol_CheckMark, config.COLOR_ACCENT)
        dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 6)

dpg.bind_theme(global_theme)

with dpg.window(tag="Primary Window"):
    dpg.add_text("PROJECT CHAOS MAGNET v3.3 // COBRA LAB (P2P ENABLED)", color=config.COLOR_ACCENT)
    
    # --- Status Header ---
    with dpg.group(horizontal=True):
        dpg.add_text("PQC STATUS: INIT...", tag="txt_pqc_status")
        dpg.add_spacer(width=20)
        dpg.add_text("UPLINK: INIT...", tag="txt_net_status")
        dpg.add_spacer(width=20)
        dpg.add_text("P2P: INIT...", tag="txt_p2p_status")

    dpg.add_separator()
    
    # --- Main Content: Left Controls + Right Stats ---
    with dpg.group(horizontal=True):
        # Left Column: Controls
        with dpg.group(width=240):
            dpg.add_text("SOURCE CONTROL")
            
            # Individual Harvester Toggles
            for name, info in harvester_info.items():
                enabled = info["available"]
                dpg.add_checkbox(
                    label=name, 
                    callback=toggle_harvester, 
                    user_data=name, 
                    default_value=False,
                    enabled=enabled
                )
                if not enabled:
                    dpg.add_text("(Not Detected)", color=config.COLOR_ERROR)
            
            dpg.add_spacer(height=10)
            dpg.add_text("NETWORK CONTROL")
            dpg.add_checkbox(label="Ayatoki Uplink", default_value=True, callback=toggle_network)
            
            # IP Address Input
            dpg.add_input_text(
                label="Target IP", 
                default_value="192.168.1.19", 
                width=120, 
                callback=callback_ip_update,
                hint="Ayatoki IP"
            )
            
            dpg.add_spacer(height=10)
            dpg.add_text("P2P ENTROPY SHARING")
            dpg.add_checkbox(label="Enable P2P", default_value=False, callback=toggle_p2p)
            
            dpg.add_input_text(
                label="Listen Port",
                default_value="9000",
                width=120,
                callback=callback_p2p_port_update,
                hint="Port"
            )
            
            dpg.add_input_text(
                label="Add Peer IP",
                default_value="",
                width=120,
                callback=callback_add_peer,
                hint="IP:Port"
            )
            
            dpg.add_spacer(height=10)
            dpg.add_text("VAULT CONTROL")
            dpg.add_button(label="MINT KEYPAIR", callback=callback_mint_pqc, width=-1)
            dpg.add_text("Waiting...", tag="txt_last_key", color=config.COLOR_ACCENT)

        # Right Column: Stats
        with dpg.group():
            dpg.add_text("BYTES HARVESTED: 0", tag="txt_bytes")
            dpg.add_text("RAW QUALITY: 0.0", tag="txt_quality", color=config.COLOR_ACCENT)
            
            dpg.add_spacer(height=5)
            dpg.add_text("--- EXTRACTION POOL ---", color=config.COLOR_ACCENT)
            dpg.add_text("Pool Fill: 0%", tag="txt_pool_fill")
            dpg.add_text("Accumulated: 0 bytes", tag="txt_pool_accum")
            dpg.add_text("Extractions: 0", tag="txt_extractions")
            dpg.add_text("Ratio: 0:1", tag="txt_ratio")

    dpg.add_spacer(height=10)
    
    # --- Entropy Graph ---
    with dpg.plot(label="Real-time RAW Entropy Quality (Pre-Extraction)", height=200, width=-1):
        dpg.add_plot_legend()
        dpg.add_plot_axis(dpg.mvXAxis, label="Time (Ticks)", no_tick_labels=True)
        with dpg.plot_axis(dpg.mvYAxis, label="Shannon Entropy"):
            dpg.set_axis_limits(dpg.last_item(), 0, 8.5)
            dpg.add_line_series([], [], label="Raw Entropy", tag="series_entropy")

    dpg.add_spacer(height=10)
    
    # --- Source Quality Breakdown ---
    dpg.add_text("SOURCE BREAKDOWN:", color=config.COLOR_ACCENT)
    dpg.add_input_text(tag="txt_source_breakdown", width=-1, height=100, multiline=True, readonly=True)
    
    dpg.add_spacer(height=10)
    
    # --- Pool State Display ---
    dpg.add_text("LIVE POOL STATE (SHA-3 MIX):")
    dpg.add_input_text(tag="txt_pool", width=-1, readonly=True)
    
    dpg.add_spacer(height=10)
    
    # --- Audit Log ---
    dpg.add_text("AUDIT LOG:")
    dpg.add_input_text(tag="txt_console", width=-1, height=150, multiline=True, readonly=True)

# --- Viewport Setup ---
dpg.create_viewport(title="Cobra Lab // ChaosMagnet v3.3 (P2P)", width=800, height=950)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("Primary Window", True)

# --- Main Loop ---
print("DEBUG: Starting GUI loop...")
while dpg.is_dearpygui_running():
    update_gui()
    dpg.render_dearpygui_frame()

# --- Cleanup ---
print("DEBUG: Shutting down...")
engine.shutdown()
dpg.destroy_context()
print("DEBUG: Clean exit.")