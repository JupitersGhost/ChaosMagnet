use pyo3::prelude::*;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use parking_lot::Mutex;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::fs;
use std::collections::{VecDeque, HashMap};
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_256;
use pqcrypto_kyber::kyber512;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use rand::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const EXTRACTION_POOL_SIZE: usize = 200;  // Raw bytes before extraction
const POOL_SIZE: usize = 1024;
const HISTORY_LEN: usize = 300;
const RCT_CUTOFF: usize = 10;
const APT_CUTOFF: f64 = 0.40;
const AUTO_MINT_THRESHOLD: f64 = 6.5;  // Min-entropy threshold

// ═══════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct EntropyExtractionPool {
    buffer: Vec<u8>,
    extractions_count: u64,
    last_extraction: f64,
    total_raw_consumed: usize,      // NEW: Track total raw bytes
    total_extracted_bytes: usize,   // NEW: Track total extracted bytes
}

impl EntropyExtractionPool {
    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(EXTRACTION_POOL_SIZE),
            extractions_count: 0,
            last_extraction: 0.0,
            total_raw_consumed: 0,
            total_extracted_bytes: 0,
        }
    }
    
    fn add_raw_bytes(&mut self, raw_data: &[u8]) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(raw_data);
        
        if self.buffer.len() >= EXTRACTION_POOL_SIZE {
            Some(self.extract())
        } else {
            None
        }
    }
    
    fn extract(&mut self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer);
        hasher.update(&self.extractions_count.to_le_bytes());
        let result = hasher.finalize();
        
        // NEW: Track raw vs extracted
        self.total_raw_consumed += self.buffer.len();
        self.total_extracted_bytes += 32;  // SHA-256 always outputs 32 bytes
        
        self.buffer.clear();
        self.extractions_count += 1;
        self.last_extraction = get_timestamp() as f64;
        
        result.to_vec()
    }
    
    fn fill_percentage(&self) -> f64 {
        (self.buffer.len() as f64 / EXTRACTION_POOL_SIZE as f64) * 100.0
    }
    
    fn accumulated_bytes(&self) -> usize {
        self.buffer.len()
    }
}

#[derive(Clone, Default)]
struct SourceMetrics {
    raw_shannon: f64,
    min_entropy: f64,
    samples: u64,
    avg_raw_entropy: f64,
    total_bits_contributed: f64,
}

// NEW: P2P Configuration
#[derive(Clone)]
struct P2PConfig {
    active: bool,
    listen_port: u16,
    peers: Vec<String>,  // List of "IP:PORT" strings
    received_count: u64,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            active: false,
            listen_port: 9000,
            peers: Vec::new(),
            received_count: 0,
        }
    }
}

struct SharedState {
    extraction_pool: EntropyExtractionPool,
    pool: [u8; 32],
    display_pool: VecDeque<u8>,
    history_raw_entropy: VecDeque<f64>,
    history_whitened_entropy: VecDeque<f64>,
    source_metrics: HashMap<String, SourceMetrics>,
    estimated_true_entropy_bits: f64,
    logs: VecDeque<String>,
    total_bytes: usize,
    sequence_id: u64,
    net_mode: bool,
    uplink_url: String,
    falcon_pk: Vec<u8>,
    falcon_sk: Vec<u8>,
    pqc_active: bool,
    harvester_states: HarvesterStates,
    p2p_config: P2PConfig,  // NEW
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
    tx_entropy: Sender<(String, Vec<u8>)>,
}

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH CHECKS
// ═══════════════════════════════════════════════════════════════════════════

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

fn passes_health_checks(data: &[u8]) -> bool {
    check_health_rct(data, RCT_CUTOFF) && check_health_apt(data, APT_CUTOFF)
}

// ═══════════════════════════════════════════════════════════════════════════
// ENTROPY CALCULATIONS
// ═══════════════════════════════════════════════════════════════════════════

fn get_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn get_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

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

fn min_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let max_count = counts.iter().max().copied().unwrap_or(0);
    let max_prob = max_count as f64 / data.len() as f64;
    if max_prob <= 0.0 || max_prob >= 1.0 { return 0.0; }
    -max_prob.log2()
}

// ═══════════════════════════════════════════════════════════════════════════
// HARVESTERS (WITH THROTTLING)
// ═══════════════════════════════════════════════════════════════════════════

fn start_trng_harvester(tx: Sender<(String, Vec<u8>)>, running: Arc<AtomicBool>, state: Arc<Mutex<SharedState>>) {
    thread::spawn(move || {
        let mut rng = rand::rngs::OsRng;
        while running.load(Ordering::Relaxed) {
            let enabled = state.lock().harvester_states.trng;
            if enabled {
                let mut buf = [0u8; 1024];
                rng.fill_bytes(&mut buf);
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
        
        // THROTTLE: Track last send time
        let last_send = Arc::new(Mutex::new(Instant::now()));
        let last_send_clone = last_send.clone();

        let stream = device.build_input_stream(
            &config.into(),
            move |data: &[f32], _: &_| {
                if !running_stream.load(Ordering::Relaxed) { return; }
                
                let enabled = state_clone.lock().harvester_states.audio;
                if !enabled { return; }
                
                // THROTTLE: Max 5 sends/second (200ms minimum interval)
                let mut last = last_send_clone.lock();
                if last.elapsed() < Duration::from_millis(200) {
                    return;  // Skip this callback
                }
                *last = Instant::now();
                drop(last);
                
                // LIMIT: Only take first 256 samples to avoid flooding
                let sample_limit = data.len().min(256);
                let mut bytes = Vec::with_capacity(sample_limit * 4);
                
                for &sample in data.iter().take(sample_limit).step_by(4) {
                    let bits = sample.to_bits();
                    bytes.extend_from_slice(&bits.to_le_bytes());
                }
                
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
                let mut raw_bytes = Vec::with_capacity(128);
                
                for cpu in sys.cpus() {
                    let usage_bits = cpu.cpu_usage().to_bits();
                    let freq = cpu.frequency();
                    raw_bytes.extend_from_slice(&usage_bits.to_le_bytes());
                    raw_bytes.extend_from_slice(&freq.to_le_bytes());
                }
                
                let nanos = get_timestamp_nanos();
                raw_bytes.extend_from_slice(&nanos.to_le_bytes());
                let mem = sys.used_memory();
                raw_bytes.extend_from_slice(&mem.to_le_bytes());
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
                    
                    let now = Instant::now();
                    let mut last = last_instant_clone.lock();
                    let delta_nanos = now.duration_since(*last).as_nanos() as u64;
                    *last = now;
                    drop(last);
                    
                    let mut payload = Vec::with_capacity(24);
                    payload.extend_from_slice(&(x as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&(y as f64).to_bits().to_le_bytes());
                    payload.extend_from_slice(&delta_nanos.to_le_bytes());
                    
                    let _ = tx.try_send(("MOUSE_MOV".to_string(), payload));
                },
                EventType::ButtonPress(btn) => {
                    let now = Instant::now();
                    let mut last = last_instant_clone.lock();
                    let delta_nanos = now.duration_since(*last).as_nanos() as u64;
                    *last = now;
                    drop(last);
                    
                    let mut payload = Vec::with_capacity(24);
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
                            let mut noise: Vec<u8> = buffer.iter()
                                .step_by(7)
                                .map(|&b| b & 0x0F)
                                .collect();
                            
                            let nanos = get_timestamp_nanos();
                            noise.extend_from_slice(&nanos.to_le_bytes());
                            
                            if let Some(ref prev_hash) = last_frame_hash {
                                for (i, b) in noise.iter_mut().enumerate().take(32) {
                                    *b ^= prev_hash[i % 32];
                                }
                            }
                            
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

// ═══════════════════════════════════════════════════════════════════════════
// P2P SERVER (NEW)
// ═══════════════════════════════════════════════════════════════════════════

fn start_p2p_server(
    tx: Sender<(String, Vec<u8>)>,
    state: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>
) {
    thread::spawn(move || {
        use std::net::TcpListener;
        use std::io::{Read, Write};
        
        let port = state.lock().p2p_config.listen_port;
        let addr = format!("0.0.0.0:{}", port);
        
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => {
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let mut lock = state.lock();
                let msg = format!("[{}] P2P: Listening on port {}", ts, port);
                if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                lock.logs.push_back(msg);
                drop(lock);
                l
            },
            Err(e) => {
                eprintln!("P2P: Failed to bind to {}: {}", addr, e);
                return;
            }
        };
        
        // Set non-blocking for graceful shutdown
        listener.set_nonblocking(true).ok();
        
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    // Check if P2P is still active
                    if !state.lock().p2p_config.active {
                        continue;
                    }
                    
                    let tx_clone = tx.clone();
                    let state_clone = state.clone();
                    
                    thread::spawn(move || {
                        let mut buffer = String::new();
                        if stream.read_to_string(&mut buffer).is_ok() {
                            // Parse HTTP request (simple POST body extraction)
                            if let Some(body_start) = buffer.find("\r\n\r\n") {
                                let body = &buffer[body_start + 4..];
                                
                                // Parse JSON payload
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                                    if let Some(payload_hex) = json["payload_hex"].as_str() {
                                        if let Ok(entropy_bytes) = hex::decode(payload_hex) {
                                            // Health check
                                            if passes_health_checks(&entropy_bytes) {
                                                // Add to processing queue
                                                let source = format!("P2P_{}", addr.ip());
                                                let _ = tx_clone.try_send((source, entropy_bytes));
                                                
                                                // Update P2P stats
                                                let mut lock = state_clone.lock();
                                                lock.p2p_config.received_count += 1;
                                                
                                                // HTTP response
                                                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                                                let _ = stream.write_all(response.as_bytes());
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Error response
                        let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 5\r\n\r\nERROR";
                        let _ = stream.write_all(response.as_bytes());
                    });
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection, sleep briefly
                    thread::sleep(Duration::from_millis(100));
                },
                Err(_) => {
                    // Other error, continue
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// MIXER THREAD (WITH P2P SUPPORT)
// ═══════════════════════════════════════════════════════════════════════════

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
            
            // Measure RAW entropy
            let raw_shannon = shannon_entropy(&data);
            let raw_min = min_entropy(&data);
            let entropy_contribution_bits = (raw_min * data.len() as f64).min(data.len() as f64 * 8.0);
            
            let mut lock = state.lock();
            
            // Feed to extraction pool
            let extracted_opt = lock.extraction_pool.add_raw_bytes(&data);
            
            // Update source metrics
            let metrics = lock.source_metrics.entry(source.clone()).or_default();
            metrics.samples += 1;
            metrics.raw_shannon = raw_shannon;
            metrics.min_entropy = raw_min;
            metrics.total_bits_contributed += entropy_contribution_bits;
            metrics.avg_raw_entropy = if metrics.samples == 1 {
                raw_shannon
            } else {
                metrics.avg_raw_entropy * 0.95 + raw_shannon * 0.05
            };
            
            lock.estimated_true_entropy_bits += entropy_contribution_bits;
            
            // Update history
            if lock.history_raw_entropy.len() >= HISTORY_LEN {
                lock.history_raw_entropy.pop_front();
            }
            lock.history_raw_entropy.push_back(raw_min);
            
            // Process extracted entropy
            if let Some(extracted) = extracted_opt {
                let extracted_shannon = shannon_entropy(&extracted);
                
                if lock.history_whitened_entropy.len() >= HISTORY_LEN {
                    lock.history_whitened_entropy.pop_front();
                }
                lock.history_whitened_entropy.push_back(extracted_shannon);
                
                // Mix into pool
                let mut pool_hasher = Sha3_256::new();
                pool_hasher.update(&lock.pool);
                pool_hasher.update(source.as_bytes());
                pool_hasher.update(&extracted);
                lock.pool = pool_hasher.finalize().into();
                
                // Update display pool
                for &b in extracted.iter() {
                    if lock.display_pool.len() >= POOL_SIZE {
                        lock.display_pool.pop_front();
                    }
                    lock.display_pool.push_back(b);
                }
                
                lock.total_bytes += extracted.len();
                lock.sequence_id += 1;
                
                // Log extraction
                let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                let msg = format!(
                    "[{}] EXTRACT #{} | 200→32 bytes | Quality:{:.2} | Source:{}",
                    ts, lock.extraction_pool.extractions_count, extracted_shannon, source
                );
                if lock.logs.len() >= 20 { lock.logs.pop_front(); }
                lock.logs.push_back(msg);
            
                // AUTO-MINT (every 10 extractions if quality is good)
                if lock.extraction_pool.extractions_count % 10 == 0
                    && raw_min > AUTO_MINT_THRESHOLD
                    && lock.pqc_active 
                {
                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let msg = format!(
                        "[{}] AUTO-MINT: Quality={:.2}, Minting keypair...", 
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
                
                // Network uplink
                let now = get_timestamp();
                if lock.net_mode && now > last_net_time {
                    last_net_time = now;
                    
                    let target = lock.uplink_url.clone();
                    let seq = lock.sequence_id;
                    let source_clone = source.clone();
                    let c = client.clone();
                    
                    let payload_hex = hex::encode(&extracted[..]);
                    let payload_size = extracted.len();
                    
                    let digest = {
                        let mut hasher = Sha3_256::new();
                        hasher.update(&data);
                        hex::encode(hasher.finalize())
                    };
                
                    let ts_epoch = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs_f64();
                    
                    let raw_min_copy = raw_min;
                    let raw_shannon_copy = raw_shannon;
                    
                    thread::spawn(move || {
                        let _ = c.post(&target)
                            .json(&serde_json::json!({
                                "node": "chaos_magnet",
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
                }
                
                // P2P distribution (send to all peers)
                if lock.p2p_config.active && !lock.p2p_config.peers.is_empty() {
                    let peers = lock.p2p_config.peers.clone();
                    let payload_hex = hex::encode(&extracted[..]);
                    let seq = lock.sequence_id;
                    let c = client.clone();
                    
                    thread::spawn(move || {
                        for peer in peers {
                            let url = format!("http://{}/ingest", peer);
                            let _ = c.post(&url)
                                .json(&serde_json::json!({
                                    "node": "chaos_magnet_p2p",
                                    "seq": seq,
                                    "timestamp": get_timestamp(),
                                    "payload_hex": payload_hex,
                                }))
                                .send();
                        }
                    });
                }
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// PYTHON CLASS
// ═══════════════════════════════════════════════════════════════════════════

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
            extraction_pool: EntropyExtractionPool::new(),
            pool: [0u8; 32],
            display_pool,
            history_raw_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            history_whitened_entropy: VecDeque::from(vec![0.0; HISTORY_LEN]),
            source_metrics: HashMap::new(),
            estimated_true_entropy_bits: 0.0,
            logs: VecDeque::from(vec!["ENGINE: Rust Core v3.3 (P2P Enabled)".to_string()]),
            total_bytes: 0,
            net_mode: true,
            uplink_url: "http://192.168.1.19:8000/ingest".to_string(),
            sequence_id: 0,
            falcon_pk: pk.as_bytes().to_vec(),
            falcon_sk: sk.as_bytes().to_vec(),
            pqc_active,
            harvester_states: HarvesterStates::default(),
            p2p_config: P2PConfig::default(),
        }));
        
        {
            let mut lock = state.lock();
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            lock.logs.push_back(format!("[{}] IDENTITY: Falcon-512 Session Key Generated", ts));
            lock.logs.push_back(format!("[{}] EXTRACTION: 200→32 byte compression", ts));
        }

        let running = Arc::new(AtomicBool::new(true));
        
        start_mixer_thread(rx, state.clone(), running.clone());
        start_p2p_server(tx.clone(), state.clone(), running.clone());
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

    fn toggle_uplink(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.net_mode = active;
        
        let status = if active { "ENABLED" } else { "PAUSED" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] Network Uplink -> {}", ts, status);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    fn toggle_p2p(&self, active: bool) {
        let mut lock = self.state.lock();
        lock.p2p_config.active = active;
        
        let status = if active { "ENABLED" } else { "PAUSED" };
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] P2P Mode -> {}", ts, status);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    fn set_p2p_port(&self, port: u16) {
        let mut lock = self.state.lock();
        lock.p2p_config.listen_port = port;
        
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let msg = format!("[{}] P2P: Listen port set to {}", ts, port);
        if lock.logs.len() >= 20 { lock.logs.pop_front(); }
        lock.logs.push_back(msg);
    }

    fn add_peer(&self, peer_addr: String) {
        let mut lock = self.state.lock();
        if !lock.p2p_config.peers.contains(&peer_addr) {
            lock.p2p_config.peers.push(peer_addr.clone());
            
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let msg = format!("[{}] P2P: Added peer {}", ts, peer_addr);
            if lock.logs.len() >= 20 { lock.logs.pop_front(); }
            lock.logs.push_back(msg);
        }
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

    fn get_metrics(&self) -> PyResult<String> {
        let lock = self.state.lock();
        
        let current_raw = lock.history_raw_entropy.back().copied().unwrap_or(0.0);
        let current_whitened = lock.history_whitened_entropy.back().copied().unwrap_or(0.0);
        
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
            "current_entropy": current_raw,
            "current_raw_entropy": current_raw,
            "current_whitened_entropy": current_whitened,
            "estimated_true_bits": lock.estimated_true_entropy_bits,
            
            // NEW: Extraction pool metrics
            "extraction_pool_fill": lock.extraction_pool.fill_percentage(),
            "extraction_pool_accumulated": lock.extraction_pool.accumulated_bytes(),
            "extractions_count": lock.extraction_pool.extractions_count,
            "total_raw_consumed": lock.extraction_pool.total_raw_consumed,
            "total_extracted_bytes": lock.extraction_pool.total_extracted_bytes,
            
            "source_quality": source_quality,
            "history": lock.history_raw_entropy.iter().collect::<Vec<_>>(),
            "history_raw": lock.history_raw_entropy.iter().collect::<Vec<_>>(),
            "history_whitened": lock.history_whitened_entropy.iter().collect::<Vec<_>>(),
            "logs": lock.logs.iter().collect::<Vec<_>>(),
            "net_mode": lock.net_mode,
            "pqc_ready": lock.pqc_active,
            
            // NEW: P2P metrics
            "p2p_active": lock.p2p_config.active,
            "p2p_port": lock.p2p_config.listen_port,
            "p2p_peer_count": lock.p2p_config.peers.len(),
            "p2p_received_count": lock.p2p_config.received_count,
        });
        
        Ok(metrics.to_string())
    }
    
    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[pymodule]
fn chaos_magnet_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ChaosEngine>()?;
    Ok(())
}