#!/usr/bin/env python3
"""
ChaosMagnet GUI - Cobra Lab
Full-featured entropy harvesting with Rust backend
"""
import dearpygui.dearpygui as dpg
import json
import chaos_magnet_core 
import config

# --- Init Rust Backend ---
try:
    engine = chaos_magnet_core.ChaosEngine() 
    print("DEBUG: Rust Core Loaded & Running.")
except Exception as e:
    print(f"FATAL: Could not load Rust core: {e}")
    exit(1)

# --- Harvester Availability Detection ---
# The Rust backend handles availability internally, but we track GUI state here
harvester_info = {
    "System/CPU": {"rust_name": "SYSTEM", "available": True},
    "Hardware/TRNG": {"rust_name": "TRNG", "available": True},
    "Audio (Mic)": {"rust_name": "AUDIO", "available": True},
    "Video (Cam)": {"rust_name": "VIDEO", "available": True},
    "HID (Mouse)": {"rust_name": "MOUSE", "available": True},
}

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

def callback_ip_update(sender, app_data):
    """Update Target IP in Rust"""
    if app_data:
        engine.set_network_target(app_data)

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
    try:
        # 1. Get Data from Rust
        raw_metrics = engine.get_metrics() 
        metrics = json.loads(raw_metrics)
        
        # 2. Update Entropy Graph
        history = metrics.get('history', [])
        if history:
            dpg.set_value("series_entropy", [list(range(len(history))), history])
        
        # 3. Update Stats
        dpg.set_value("txt_bytes", f"Bytes Harvested: {metrics['total_bytes']}")
        dpg.set_value("txt_quality", f"Current Pool Entropy: {metrics['current_entropy']:.4f} / 8.0")
        dpg.set_value("txt_pool", metrics['pool_hex'])
        
        # 4. Update Logs (last 15 lines)
        logs = metrics.get('logs', [])
        log_text = "\n".join(logs[-15:])
        dpg.set_value("txt_console", log_text)

        # 5. Dynamic Status Indicators
        # Network Status
        if metrics["net_mode"]:
            dpg.configure_item("txt_net_status", default_value="UPLINK: ONLINE (Ayatoki)", color=config.COLOR_PLOT_LINE)
        else:
            dpg.configure_item("txt_net_status", default_value="UPLINK: OFFLINE (Local Mode)", color=config.COLOR_WARN)
             
        # PQC Status
        if metrics.get("pqc_ready", False):
            dpg.configure_item("txt_pqc_status", default_value="PQC STATUS: ACTIVE (Kyber/Falcon)", color=config.COLOR_PLOT_LINE)
        else:
            dpg.configure_item("txt_pqc_status", default_value="PQC STATUS: DISABLED", color=config.COLOR_ERROR)

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
    dpg.add_text("PROJECT CHAOS MAGNET // COBRA LAB (RUST CORE)", color=config.COLOR_ACCENT)
    
    # --- Status Header ---
    with dpg.group(horizontal=True):
        dpg.add_text("PQC STATUS: INIT...", tag="txt_pqc_status")
        dpg.add_spacer(width=20)
        dpg.add_text("UPLINK: INIT...", tag="txt_net_status")

    dpg.add_separator()
    
    # --- Main Content: Left Controls + Right Stats ---
    with dpg.group(horizontal=True):
        # Left Column: Controls
        with dpg.group(width=220):
            dpg.add_text("SOURCE CONTROL")
            
            # Individual Harvester Toggles (matches Python version)
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
            dpg.add_text("VAULT CONTROL")
            dpg.add_button(label="MINT KEYPAIR", callback=callback_mint_pqc, width=-1)
            dpg.add_text("Waiting...", tag="txt_last_key", color=config.COLOR_ACCENT)

        # Right Column: Stats
        with dpg.group():
            dpg.add_text("BYTES HARVESTED: 0", tag="txt_bytes")
            dpg.add_text("POOL QUALITY: 0.0", tag="txt_quality", color=config.COLOR_ACCENT)

    dpg.add_spacer(height=10)
    
    # --- Entropy Graph ---
    with dpg.plot(label="Real-time Entropy Quality (Rust Backend)", height=200, width=-1):
        dpg.add_plot_legend()
        dpg.add_plot_axis(dpg.mvXAxis, label="Time (Ticks)", no_tick_labels=True)
        with dpg.plot_axis(dpg.mvYAxis, label="Shannon Entropy"):
            dpg.set_axis_limits(dpg.last_item(), 0, 8.5)
            dpg.add_line_series([], [], label="Pool Entropy", tag="series_entropy")

    dpg.add_spacer(height=10)
    
    # --- Pool State Display ---
    dpg.add_text("LIVE POOL STATE (SHA-3 MIX):")
    dpg.add_input_text(tag="txt_pool", width=-1, readonly=True)
    
    dpg.add_spacer(height=10)
    
    # --- Audit Log ---
    dpg.add_text("AUDIT LOG:")
    dpg.add_input_text(tag="txt_console", width=-1, height=150, multiline=True, readonly=True)

# --- Viewport Setup ---
dpg.create_viewport(title="Cobra Lab // ChaosMagnet (Rust)", width=700, height=850)
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