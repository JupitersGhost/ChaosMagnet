use pyo3::prelude::*;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use parking_lot::Mutex;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::fs;
use std::collections::{VecDeque, HashMap};
use sha3::{Digest, Sha3_256};
use pqcrypto_kyber::kyber512;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use rand::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION (Mirrors config.py)
// ═══════════════════════════════════════════════════════════════════════════════

const POOL_SIZE: usize = 1024;        // Display pool size (for entropy graph)
const HISTORY_LEN: usize = 300;       // History points for GUI graph
const RCT_CUTOFF: usize = 10;         // Repetition Count Test threshold
const APT_CUTOFF: f64 = 0.40;         // Adaptive Proportion Test threshold
const AUTO_MINT_THRESHOLD: f64 = 5.5; // Use RAW min-entropy threshold (more realistic!)

// ═══════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-source entropy quality tracking (measures RAW input, not SHA-3 output)
#[derive(Clone, Default)]
struct SourceMetrics {
    /// Shannon entropy of raw data (before whitening)
    raw_shannon: f64,
    /// Min-entropy estimate (more conservative, NIST-preferred)
    min_entropy: f64,
    /// Sample count for this source
    samples: u64,
    /// Running average of raw entropy (exponential decay)
    avg_raw_entropy: f64,
    /// Total estimated true entropy bits contributed
    total_bits_contributed: f64,
}

struct SharedState {
    // Crypto State (Always 32 bytes - the actual mixing pool)
    pool: [u8; 32],
    
    // Display Pool (Rolling buffer for entropy graph - matches Python's deque)
    display_pool: VecDeque<u8>,
    
    // Entropy History - NOW TRACKS BOTH RAW AND WHITENED
    history_raw_entropy: VecDeque<f64>,      // True source quality (what you SHOULD watch)
    history_whitened_entropy: VecDeque<f64>, // After SHA-3 (always ~7.9, less useful)
    
    // Per-source quality tracking
    source_metrics: HashMap<String, SourceMetrics>,
    
    // Conservative accumulated entropy estimate
    estimated_true_entropy_bits: f64,
    
    // Logs
    logs: VecDeque<String>,
    
    // Metrics
    total_bytes: usize,
    sequence_id: u64,
    
    // Network Config
    net_mode: bool,
    uplink_url: String,
    
    // PQC Identity (Session Keys)
    falcon_pk: Vec<u8>,
    falcon_sk: Vec<u8>,
    pqc_active: bool,
    
    // Harvester States (for individual toggle control)
    harvester_states: HarvesterStates,
}

#[derive(Clone)]
struct HarvesterStates {
    trng: bool,
    audio: bool,
    system: bool,
    mouse: bool,
    video: bool,
}

impl Default for HarvesterStates {
    fn default() -> Self {
        Self {
            trng: false,
            audio: false,
            system: false,
            mouse: false,
            video: false,
        }
    }
}

#[pyclass]
struct ChaosEngine {
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    tx_entropy: Sender<(String, Vec<u8>)>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECKS (NIST SP 800-90B Style)
// ═══════════════════════════════════════════════════════════════════════════════

/// Repetition Count Test (RCT)
/// Fails if any single value repeats continuously more than 'cutoff' times.
fn check_health_rct(data: &[u8], cutoff: usize) -> bool {
    if data.is_empty() { return true; }
    
    let mut max_repeats = 0usize;
    let mut current_repeats = 1usize;
    let mut last_val = data[0];
    
    for &byte in &data[1..] {
        if byte == last_val {
            current_repeats += 1;
        } else {
            max_repeats = max_repeats.max(current_repeats);
            current_repeats = 1;
            last_val = byte;
        }
    }
    max_repeats = max_repeats.max(current_repeats);
    
    max_repeats < cutoff
}

/// Adaptive Proportion Test (APT)
/// Fails if a single byte value appears too often (>cutoff% of the sample)
fn check_health_apt(data: &[u8], cutoff: f64) -> bool {
    if data.len() < 10 { return false; }
    
    let mut counts = [0usize; 256];
    let mut max_count = 0usize;
    
    for &b in data {
        let c = counts[b as usize] + 1;
        counts[b as usize] = c;
        if c > max_count { max_count = c; }
    }
    
    let ratio = max_count as f64 / data.len() as f64;
    ratio < cutoff
}

/// Combined health check (both RCT and APT must pass)
fn passes_health_checks(data: &[u8]) -> bool {
    check_health_rct(data, RCT_CUTOFF) && check_health_apt(data, APT_CUTOFF)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY CALCULATION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn get_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Get high-resolution timestamp in nanoseconds (much better entropy than seconds!)
fn get_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// Shannon Entropy: -Σ p(x) * log2(p(x))
/// This measures the average information content per symbol.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    
    let mut entropy = 0.0;
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Min-Entropy: -log2(max_probability)
/// This is NIST SP 800-90B's preferred metric - more conservative than Shannon.
/// Assumes attacker always guesses the most likely symbol.
fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    
    let max_count = counts.iter().max().copied().unwrap_or(0);
    let max_prob = max_count as f64 / data.len() as f64;
    
    if max_prob <= 0.0 || max_prob >= 1.0 {
        return 0.0;
    }
    
    -max_prob.log2()
}

/// Collision Entropy (Rényi entropy of order 2)
/// H2 = -log2(Σ p(x)²)
/// Useful middle ground between Shannon and min-entropy.
fn collision_entropy(data: &[u8]) -> f64 {
    if data.len() < 2 { return 0.0; }
    
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    
    let n = data.len() as f64;
    let sum_sq: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p
        })
        .sum();
    
    if sum_sq <= 0.0 { return 0.0; }
    
    -sum_sq.log2()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HARVESTERS (IMPROVED - Binary encoding, high-res timestamps)
// ═══════════════════════════════════════════════════════════════════════════════

fn start_trng_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        let mut rng = rand::rngs::OsRng;
        while running.load(Ordering::Relaxed) {
            let enabled = state.lock().harvester_states.trng;
            if enabled {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
                
                // TRNG data is high quality - but still check
                if passes_health_checks(&buf) {
                    let _ = tx.try_send(("TRNG".to_string(), buf.to_vec()));
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
}

fn start_audio_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        
        let host = cpal::default_host();
        let device = match host.default_input_device() {
            Some(d) => d,
            None => return,
        };
        
        let config = match device.default_input_config() {
            Ok(c) => c,
            Err(_) => return,
        };
        
        let tx_clone = tx.clone();
        let running_stream = running.clone();
        let state_clone = state.clone();

        let stream = device.build_input_stream(
            &config.into(),
            move |data: &[f32], _: &_| {
                if !running_stream.load(Ordering::Relaxed) { return; }
                
                let enabled = state_clone.lock().harvester_states.audio;
                if !enabled { return; }
                
                // IMPROVED: Extract raw bits from float representation
                // The LSBs of audio samples contain thermal noise
                let mut bytes = Vec::with_capacity(data.len() * 4);
                for &sample in data.iter().step_by(4) {
                    // Get the raw IEEE 754 bits - LSBs have the noise
                    let bits = sample.to_bits();
                    bytes.extend_from_slice(&bits.to_le_bytes());
                }
                
                // Add high-resolution timing jitter
                let nanos = get_timestamp_nanos();
                bytes.extend_from_slice(&nanos.to_le_bytes());
                
                if passes_health_checks(&bytes) {
                    let _ = tx_clone.try_send(("AUDIO".to_string(), bytes));
                }
            },
            |_| {}, None
        );

        if let Ok(s) = stream {
            let _ = s.play();
            while running.load(Ordering::Relaxed) { 
                thread::sleep(Duration::from_secs(1)); 
            }
        }
    });
}

fn start_system_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        use sysinfo::System;
        let mut sys = System::new_all();
        
        while running.load(Ordering::Relaxed) {
            let enabled = state.lock().harvester_states.system;
            if enabled {
                sys.refresh_all();
                
                // IMPROVED: Use raw binary, not ASCII strings!
                let mut raw_bytes = Vec::with_capacity(128);
                
                for cpu in sys.cpus() {
                    // Extract raw float bits (not ASCII "45.23" which wastes entropy)
                    let usage_bits = cpu.cpu_usage().to_bits();
                    let freq = cpu.frequency();
                    
                    raw_bytes.extend_from_slice(&usage_bits.to_le_bytes());
                    raw_bytes.extend_from_slice(&freq.to_le_bytes());
                }
                
                // High-resolution timestamp (nanoseconds have jitter)
                let nanos = get_timestamp_nanos();
                raw_bytes.extend_from_slice(&nanos.to_le_bytes());
                
                // Memory state adds entropy
                let mem = sys.used_memory();
                raw_bytes.extend_from_slice(&mem.to_le_bytes());
                
                // Available memory fluctuates
                let avail = sys.available_memory();
                raw_bytes.extend_from_slice(&avail.to_le_bytes());
                
                if !raw_bytes.is_empty() && passes_health_checks(&raw_bytes) {
                    let _ = tx.try_send(("SYS".to_string(), raw_bytes));
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
}

fn start_mouse_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        use rdev::{listen, EventType};
        
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let last_instant = Arc::new(Mutex::new(Instant::now()));
        let last_instant_clone = last_instant.clone();
        
        let callback = move |event: rdev::Event| {
            if !running.load(Ordering::Relaxed) { return; }
            
            let enabled = state.lock().harvester_states.mouse;
            if !enabled { return; }
            
            match event.event_type {
                EventType::MouseMove { x, y } => {
                    let count = counter_clone.fetch_add(1, Ordering::Relaxed);
                    if count % 20 != 0 { return; }
                    
                    // IMPROVED: High-resolution inter-event timing is the REAL entropy source!
                    let now = Instant::now();
                    let mut last = last_instant_clone.lock();
                    let delta_nanos = now.duration_since(*last).as_nanos() as u64;
                    *last = now;
                    drop(last);
                    
                    // Pack as raw bytes, not ASCII
                    let mut payload = Vec::with_capacity(24);
                    payload.extend_from_slice(&(x as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&(y as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&delta_nanos.to_le_bytes()); // This is the gold!
                    
                    let _ = tx.try_send(("MOUSE_MOV".to_string(), payload));
                },
                EventType::ButtonPress(btn) => {
                    let now = Instant::now();
                    let mut last = last_instant_clone.lock();
                    let delta_nanos = now.duration_since(*last).as_nanos() as u64;
                    *last = now;
                    drop(last);
                    
                    let mut payload = Vec::with_capacity(24);
                    // Button enum isn't unit-only, so hash its debug representation
                    let btn_bytes = format!("{:?}", btn).into_bytes();
                    payload.extend_from_slice(&btn_bytes);
                    payload.extend_from_slice(&delta_nanos.to_le_bytes());
                    payload.extend_from_slice(&get_timestamp_nanos().to_le_bytes());
                    
                    let _ = tx.try_send(("MOUSE_CLK".to_string(), payload));
                }
                _ => {}
            }
        };
        
        let _ = listen(callback);
    });
}

fn start_video_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        use nokhwa::pixel_format::RgbFormat;
        use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
        use nokhwa::Camera;
        
        let index = CameraIndex::Index(0);
        let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
        
        if let Ok(mut camera) = Camera::new(index, format) {
            if camera.open_stream().is_ok() {
                let mut last_frame_hash: Option<[u8; 32]> = None;
                
                while running.load(Ordering::Relaxed) {
                    let enabled = state.lock().harvester_states.video;
                    if enabled {
                        if let Ok(frame) = camera.frame() {
                            let buffer = frame.buffer();
                            
                            // IMPROVED: Extract LSBs which contain sensor noise
                            // Also XOR with previous frame to get temporal noise
                            let mut noise: Vec<u8> = buffer.iter()
                                .step_by(7)
                                .map(|&b| b & 0x0F)  // Keep only low 4 bits (noise)
                                .collect();
                            
                            // Add frame timing jitter
                            let nanos = get_timestamp_nanos();
                            noise.extend_from_slice(&nanos.to_le_bytes());
                            
                            // XOR with previous frame hash for temporal decorrelation
                            if let Some(ref prev_hash) = last_frame_hash {
                                for (i, b) in noise.iter_mut().enumerate().take(32) {
                                    *b ^= prev_hash[i % 32];
                                }
                            }
                            
                            // Update frame hash
                            let mut hasher = Sha3_256::new();
                            hasher.update(&noise);
                            last_frame_hash = Some(hasher.finalize().into());
                            
                            if passes_health_checks(&noise) {
                                let _ = tx.try_send(("VIDEO".to_string(), noise));
                            }
                        }
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// MIXER THREAD (The Heart of the Engine - NOW WITH PROPER ENTROPY TRACKING)
// ═══════════════════════════════════════════════════════════════════════════════

fn start_mixer_thread(
    rx: Receiver<(String, Vec<u8>)>,
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>
) {
    thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        
        let mut last_net_time = 0u64;
        
        while running.load(Ordering::Relaxed) {
            let (source, data) = match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(d) => d,
                Err(_) => continue,
            };
            
            // ═══════════════════════════════════════════════════════════════
            // KEY FIX: Measure entropy BEFORE whitening!
            // ═══════════════════════════════════════════════════════════════
            let raw_shannon = shannon_entropy(&data);
            let raw_min = min_entropy(&data);
            let _raw_collision = collision_entropy(&data);
            
            // Conservative entropy contribution estimate:
            // Use min-entropy (worst case) scaled by data size
            // But cap at data.len() * 8 bits maximum
            let entropy_contribution_bits = (raw_min * data.len() as f64).min(data.len() as f64 * 8.0);
            
            // SHA-3 Whitening (compress raw entropy)
            let whitened = {
                let mut hasher = Sha3_256::new();
                hasher.update(&data);
                hasher.finalize()
            };
            let whitened_shannon = shannon_entropy(&whitened);
            
            let mut lock = state.lock();
            
            // ═══════════════════════════════════════════════════════════════
            // Update per-source metrics with RAW data quality
            // ═══════════════════════════════════════════════════════════════
            let metrics = lock.source_metrics.entry(source.clone()).or_default();
            metrics.samples += 1;
            metrics.raw_shannon = raw_shannon;
            metrics.min_entropy = raw_min;
            metrics.total_bits_contributed += entropy_contribution_bits;
            // Exponential moving average (0.95 decay)
            metrics.avg_raw_entropy = if metrics.samples == 1 {
                raw_shannon
            } else {
                metrics.avg_raw_entropy * 0.95 + raw_shannon * 0.05
            };
            
            // Track conservative accumulated entropy
            lock.estimated_true_entropy_bits += entropy_contribution_bits;
            
            // Update BOTH history tracks
            if lock.history_raw_entropy.len() >= HISTORY_LEN {
                lock.history_raw_entropy.pop_front();
            }
            lock.history_raw_entropy.push_back(raw_min); // Show min-entropy (conservative)
            
            if lock.history_whitened_entropy.len() >= HISTORY_LEN {
                lock.history_whitened_entropy.pop_front();
            }
            lock.history_whitened_entropy.push_back(whitened_shannon);
            
            // 1. Mix into Crypto Pool
            let mut pool_hasher = Sha3_256::new();
            pool_hasher.update(&lock.pool);
            pool_hasher.update(source.as_bytes());
            pool_hasher.update(&whitened);
            lock.pool = pool_hasher.finalize().into();
            
            // 2. Update Display Pool (rolling buffer for GUI)
            for &b in whitened.iter() {
                if lock.display_pool.len() >= POOL_SIZE {
                    lock.display_pool.pop_front();
                }
                lock.display_pool.push_back(b);
            }
            
            lock.total_bytes += whitened.len();
            lock.sequence_id += 1;
            
            // 3. Periodic Logging - NOW SHOWS RAW VS WHITENED
            if lock.sequence_id % 50 == 0 {
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let msg = format!(
                    "[{}] {} | Raw:{:.2} Min:{:.2} | SHA3:{:.2} | TrueBits:{:.0}",
                    ts, source, raw_shannon, raw_min, whitened_shannon,
                    lock.estimated_true_entropy_bits
                );
                if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                lock.logs.push_back(msg);
            }
            
            // ═══════════════════════════════════════════════════════════════
            // AUTONOMOUS MINTING - Now uses RAW min-entropy threshold!
            // ═══════════════════════════════════════════════════════════════
            if lock.total_bytes % 320 == 0 
                && raw_min > AUTO_MINT_THRESHOLD  // Use min-entropy, not whitened!
                && lock.pqc_active 
            {
                if lock.sequence_id % 500 == 0 {
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let msg = format!(
                        "[{}] AUTONOMOUS: High quality source (min:{:.2}). Minting...", 
                        ts, raw_min
                    );
                    if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                    lock.logs.push_back(msg);
                    
                    let (kyber_pk, kyber_sk) = kyber512::keypair();
                    
                    let mut context_hasher = Sha3_256::new();
                    context_hasher.update(&lock.pool);
                    context_hasher.update(kyber_pk.as_bytes());
                    let context = context_hasher.finalize();
                    
                    if let Ok(falcon_secret) = falcon512::SecretKey::from_bytes(&lock.falcon_sk) {
                        let signature = falcon512::detached_sign(&context, &falcon_secret);
                        let timestamp = get_timestamp();
                        
                        let bundle = serde_json::json!({
                            "type": "COBRA_PQC_BUNDLE",
                            "requester": "RUST_AUTO",
                            "timestamp": timestamp,
                            "raw_min_entropy": raw_min,
                            "accumulated_true_bits": lock.estimated_true_entropy_bits,
                            "kyber_pk": hex::encode(kyber_pk.as_bytes()),
                            "kyber_sk": hex::encode(kyber_sk.as_bytes()),
                            "falcon_sig": hex::encode(signature.as_bytes()),
                            "falcon_signer_pk": hex::encode(&lock.falcon_pk),
                        });
                        
                        let filename = format!("keys/key_{}_{}.json", timestamp, hex::encode(&kyber_pk.as_bytes()[0..4]));
                        if let Ok(file) = fs::File::create(&filename) {
                            let _ = serde_json::to_writer_pretty(file, &bundle);
                            
                            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                            let msg = format!("[{}] VAULT: Saved {}", ts, filename);
                            if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                            lock.logs.push_back(msg);
                        }
                    }
                }
            }
            
            // 5. Network Uplink
            let now = get_timestamp();
            if lock.net_mode && now > last_net_time {
                last_net_time = now;
                
                let target = lock.uplink_url.clone();
                let seq = lock.sequence_id;
                let source_clone = source.clone();
                let c = client.clone();
                
                let payload_hex = hex::encode(&whitened[..]);
                let payload_size = whitened.len();
                
                let digest = {
                    let mut hasher = Sha3_256::new();
                    hasher.update(&data);
                    hex::encode(hasher.finalize())
                };
                
                let ts_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64();
                
                // Include RAW entropy estimate in uplink!
                let raw_min_copy = raw_min;
                let raw_shannon_copy = raw_shannon;
                
                thread::spawn(move || {
                    let _ = c.post(&target)
                        .json(&serde_json::json!({
                            "node": "mitsu_chaos_magnet",
                            "seq": seq,
                            "timestamp": get_timestamp(),
                            "ts_epoch": ts_epoch,
                            "entropy_estimate_raw_shannon": raw_shannon_copy,
                            "entropy_estimate_raw_min": raw_min_copy,
                            "health": "OK",
                            "source": source_clone,
                            "metrics": {"size": payload_size},
                            "payload_hex": payload_hex,
                            "digest": digest
                        }))
                        .send();
                });
                
                if seq % 50 == 0 {
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let msg = format!("[{}] UPLINK: Sent Seq {} to Ayatoki", ts, seq);
                    if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                    lock.logs.push_back(msg);
                }
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// PYTHON CLASS IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

#[pymethods]
impl ChaosEngine {
    #[new]
    fn new() -> Self {
        let (tx, rx) = bounded(1000);
        let _ = fs::create_dir_all("keys");
        
        let (pk, sk) = falcon512::keypair();
        let pqc_active = true;
        
        let mut display_pool = VecDeque::with_capacity(POOL_SIZE);
        display_pool.extend(vec![0u8; POOL_SIZE]);
        
        let state = Arc::new(Mutex::new(SharedState {
            pool: [0u8; 32],
            display_pool,
            history_raw_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            history_whitened_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            source_metrics: HashMap::new(),
            estimated_true_entropy_bits: 0.0,
            logs: VecDeque::from(vec!["ENGINE: Rust Core v2.0 (Raw Entropy Tracking)".to_string()]),
            total_bytes: 0,
            net_mode: true,
            uplink_url: "http://192.168.1.19:8000/ingest".to_string(),
            sequence_id: 0,
            falcon_pk: pk.as_bytes().to_vec(),
            falcon_sk: sk.as_bytes().to_vec(),
            pqc_active,
            harvester_states: HarvesterStates::default(),
        }));
        
        {
            let mut lock = state.lock();
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            lock.logs.push_back(format!("[{}] IDENTITY: Falcon-512 Session Key Generated", ts));
            lock.logs.push_back(format!("[{}] NOTE: Now tracking RAW entropy (pre-SHA3)", ts));
        }

        let running = Arc::new(AtomicBool::new(true));
        
        start_mixer_thread(rx, state.clone(), running.clone());
        start_trng_harvester(tx.clone(), running.clone(), state.clone());
        start_audio_harvester(tx.clone(), running.clone(), state.clone());
        start_system_harvester(tx.clone(), running.clone(), state.clone());
        start_mouse_harvester(tx.clone(), running.clone(), state.clone());
        start_video_harvester(tx.clone(), running.clone(), state.clone());

        ChaosEngine { state, running, tx_entropy: tx }
    }

    fn toggle_harvester(&self, name: String, active: bool) {
        let mut lock = self.state.lock();
        match name.to_uppercase().as_str() {
            "TRNG" | "HARDWARE/TRNG" => lock.harvester_states.trng = active,
            "AUDIO" | "AUDIO (MIC)" => lock.harvester_states.audio = active,
            "SYS" | "SYSTEM" | "SYSTEM/CPU" => lock.harvester_states.system = active,
            "MOUSE" | "HID (MOUSE)" => lock.harvester_states.mouse = active,
            "VIDEO" | "VIDEO (CAM)" => lock.harvester_states.video = active,
            _ => {}
        }
        
        let status = if active { "Active" } else { "Inactive" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] Toggle: {} -> {}", ts, name, status);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    #[pyo3(signature = (requester=None))]
    fn mint_pqc_bundle(&self, requester: Option<String>) -> PyResult<String> {
        let requester = requester.unwrap_or_else(|| "LOCAL".to_string());
        let mut lock = self.state.lock();
        
        if !lock.pqc_active {
            return Ok("Error: PQC Engine Offline".to_string());
        }
        
        let (kyber_pk, kyber_sk) = kyber512::keypair();
        
        let mut context_hasher = Sha3_256::new();
        context_hasher.update(&lock.pool);
        context_hasher.update(kyber_pk.as_bytes());
        let context = context_hasher.finalize();
        
        let falcon_secret = falcon512::SecretKey::from_bytes(&lock.falcon_sk)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let signature = falcon512::detached_sign(&context, &falcon_secret);
        let timestamp = get_timestamp();

        let bundle = serde_json::json!({
            "type": "COBRA_PQC_BUNDLE",
            "requester": requester,
            "timestamp": timestamp,
            "accumulated_true_bits": lock.estimated_true_entropy_bits,
            "kyber_pk": hex::encode(kyber_pk.as_bytes()),
            "kyber_sk": hex::encode(kyber_sk.as_bytes()),
            "falcon_sig": hex::encode(signature.as_bytes()),
            "falcon_signer_pk": hex::encode(&lock.falcon_pk),
        });

        let filename = format!("keys/key_{}_{}.json", timestamp, hex::encode(&kyber_pk.as_bytes()[0..4]));
        if let Ok(file) = fs::File::create(&filename) {
            let _ = serde_json::to_writer_pretty(file, &bundle);
        }

        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] VAULT: Saved {}", ts, filename);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);

        Ok(format!("Generated {}", filename))
    }

    fn set_network_target(&self, ip: String) {
        let mut lock = self.state.lock();
        lock.uplink_url = format!("http://{}:8000/ingest", ip);
        
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] NET: Target set to {}", ts, ip);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    fn toggle_uplink(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.net_mode = active;
        
        let status = if active { "ENABLED" } else { "PAUSED" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] MANUAL: Network Uplink -> {}", ts, status);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    /// Get current metrics - NOW INCLUDES RAW ENTROPY DATA
    fn get_metrics(&self) -> PyResult<String> {
        let lock = self.state.lock();
        
        // Get current raw entropy (last value, or 0)
        let current_raw = lock.history_raw_entropy.back().copied().unwrap_or(0.0);
        let current_whitened = lock.history_whitened_entropy.back().copied().unwrap_or(0.0);
        
        // Build per-source quality report
        let source_quality: HashMap<String, serde_json::Value> = lock.source_metrics.iter()
            .map(|(name, m)| {
                (name.clone(), serde_json::json!({
                    "raw_shannon": m.raw_shannon,
                    "min_entropy": m.min_entropy,
                    "avg_entropy": m.avg_raw_entropy,
                    "samples": m.samples,
                    "total_bits": m.total_bits_contributed,
                }))
            })
            .collect();
        
        let metrics = serde_json::json!({
            "pool_hex": hex::encode(lock.pool).to_uppercase(),
            "total_bytes": lock.total_bytes,
            
            // NEW: Both entropy metrics
            "current_entropy": current_raw,           // For backward compat, now shows RAW
            "current_raw_entropy": current_raw,       // Explicit raw
            "current_whitened_entropy": current_whitened, // SHA-3 output (always ~7.9)
            
            // NEW: Conservative true entropy estimate
            "estimated_true_bits": lock.estimated_true_entropy_bits,
            
            // NEW: Per-source breakdown
            "source_quality": source_quality,
            
            // Both history tracks for GUI (raw is more useful!)
            "history": lock.history_raw_entropy.iter().collect::<Vec<_>>(),
            "history_raw": lock.history_raw_entropy.iter().collect::<Vec<_>>(),
            "history_whitened": lock.history_whitened_entropy.iter().collect::<Vec<_>>(),
            
            "logs": lock.logs.iter().collect::<Vec<_>>(),
            "net_mode": lock.net_mode,
            "pqc_ready": lock.pqc_active,
        });
        
        Ok(metrics.to_string())
    }
    
    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════════

#[pymodule]
fn chaos_magnet_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ChaosEngine>()?;
    Ok(())
}