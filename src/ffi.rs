//! FFI bindings for mobile platforms (Android/iOS)
//!
//! These functions are called from Dart via FFI.

use crate::{DohProxyServer, ProxyConfig};
use std::ffi::{c_char, c_int, CStr};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

static RUNTIME: std::sync::OnceLock<Runtime> = std::sync::OnceLock::new();
static SERVER: std::sync::OnceLock<Arc<RwLock<Option<Arc<DohProxyServer>>>>> = std::sync::OnceLock::new();
static PORT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

fn get_server_holder() -> &'static Arc<RwLock<Option<Arc<DohProxyServer>>>> {
    SERVER.get_or_init(|| Arc::new(RwLock::new(None)))
}

/// Start the DOH proxy server with DOH server URL
/// Returns the port number on success, or -1 on failure
///
/// # Arguments
/// * `port` - Port to bind (0 for auto-select)
/// * `prefer_ipv6` - Whether to prefer IPv6 addresses
/// * `doh_server` - DOH server URL (null-terminated C string, or null for default)
#[no_mangle]
pub extern "C" fn doh_proxy_start_with_server(
    port: c_int,
    prefer_ipv6: c_int,
    doh_server: *const c_char,
) -> c_int {
    // Initialize logging
    doh_proxy_init_logging();

    // Parse DOH server URL from C string
    let doh_url = if doh_server.is_null() {
        "cloudflare".to_string()
    } else {
        match unsafe { CStr::from_ptr(doh_server) }.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => "cloudflare".to_string(),
        }
    };

    let config = ProxyConfig {
        bind_port: port as u16,
        prefer_ipv6: prefer_ipv6 != 0,
        doh_server: doh_url,
        ..Default::default()
    };

    start_server_with_config(config)
}

/// Start the DOH proxy server with a JSON configuration payload
/// Returns the port number on success, or -1 on failure
#[no_mangle]
pub extern "C" fn doh_proxy_start_with_config_json(config_json: *const c_char) -> c_int {
    doh_proxy_init_logging();

    if config_json.is_null() {
        tracing::error!("Config JSON pointer is null");
        return -1;
    }

    let config_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            tracing::error!("Invalid config JSON string");
            return -1;
        }
    };

    let config: ProxyConfig = match serde_json::from_str(config_str) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("Failed to parse config JSON: {}", error);
            return -1;
        }
    };

    start_server_with_config(config)
}

/// Start the DOH proxy server (legacy API, uses Cloudflare DOH)
/// Returns the port number on success, or -1 on failure
#[no_mangle]
pub extern "C" fn doh_proxy_start(port: c_int, prefer_ipv6: c_int) -> c_int {
    // Initialize logging
    doh_proxy_init_logging();

    let config = ProxyConfig {
        bind_port: port as u16,
        prefer_ipv6: prefer_ipv6 != 0,
        ..Default::default()
    };

    start_server_with_config(config)
}

fn start_server_with_config(config: ProxyConfig) -> c_int {

    let rt = get_runtime();

    // Create the server
    let server = match rt.block_on(async { DohProxyServer::new(config).await }) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!("Failed to create DOH proxy server: {}", e);
            return -1;
        }
    };

    // Store the server
    let server_holder = get_server_holder();
    let server_clone = server.clone();
    rt.block_on(async {
        let mut guard = server_holder.write().await;
        *guard = Some(server);
    });

    // Start server in background
    rt.spawn(async move {
        if let Err(e) = server_clone.start().await {
            tracing::error!("DOH proxy server error: {}", e);
        }
    });

    // Wait a bit for server to bind
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Get the actual port
    let actual_port = rt.block_on(async {
        let guard = server_holder.read().await;
        if let Some(ref server) = *guard {
            server.port().unwrap_or(0) as c_int
        } else {
            0
        }
    });

    if actual_port > 0 {
        PORT.store(actual_port, std::sync::atomic::Ordering::SeqCst);
        tracing::info!("DOH proxy started on port {}", actual_port);
        actual_port
    } else {
        tracing::error!("Failed to get DOH proxy port");
        -1
    }
}

/// Stop the DOH proxy server
#[no_mangle]
pub extern "C" fn doh_proxy_stop() {
    let rt = get_runtime();
    let server_holder = get_server_holder();

    rt.block_on(async {
        let mut guard = server_holder.write().await;
        if let Some(ref server) = *guard {
            server.stop();
            tracing::info!("DOH proxy stopped");
        }
        *guard = None;
    });

    PORT.store(0, std::sync::atomic::Ordering::SeqCst);
}

/// Check if the DOH proxy is running
/// Returns 1 if running, 0 if not
#[no_mangle]
pub extern "C" fn doh_proxy_is_running() -> c_int {
    if PORT.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        1
    } else {
        0
    }
}

/// Get the DOH proxy port
/// Returns the port number, or 0 if not running
#[no_mangle]
pub extern "C" fn doh_proxy_get_port() -> c_int {
    PORT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Lookup ECH config for a host via DOH DNS HTTPS record.
/// Returns a pointer to a JSON string: {"ok":true,"data":"<base64>"} or {"ok":false,"error":"..."}
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_ech_config(
    host: *const c_char,
    doh_server: *const c_char,
) -> *mut c_char {
    use base64::Engine;
    use crate::dns::DnsResolver;

    doh_proxy_init_logging();

    let host_str = if host.is_null() {
        return error_json("host is null");
    } else {
        match unsafe { CStr::from_ptr(host) }.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => return error_json("invalid host"),
        }
    };

    let doh_url = if doh_server.is_null() {
        "https://cloudflare-dns.com/dns-query".to_string()
    } else {
        match unsafe { CStr::from_ptr(doh_server) }.to_str() {
            Ok(s) if !s.is_empty() => s.to_string(),
            _ => "https://cloudflare-dns.com/dns-query".to_string(),
        }
    };

    let rt = get_runtime();
    let result = rt.block_on(async {
        let resolver = DnsResolver::new(&doh_url, None, false, None).await?;
        resolver.lookup_ech_config(&host_str).await
    });

    match result {
        Ok(Some(ech_bytes)) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(ech_bytes.as_ref());
            let json = format!(r#"{{"ok":true,"data":"{}"}}"#, b64);
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Ok(None) => error_json("no ECH config found"),
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Free a string returned by doh_proxy_lookup_ech_config
#[no_mangle]
pub extern "C" fn doh_proxy_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = std::ffi::CString::from_raw(ptr);
        }
    }
}

fn error_json(msg: &str) -> *mut c_char {
    let json = format!(r#"{{"ok":false,"error":"{}"}}"#, msg.replace('"', r#"\""#));
    match std::ffi::CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Initialize logging (call once at startup)
#[no_mangle]
pub extern "C" fn doh_proxy_init_logging() {
    #[cfg(target_os = "android")]
    {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::from_default_env()
            .add_directive("doh_proxy=info".parse().unwrap())
            .add_directive("rustls=warn".parse().unwrap())
            .add_directive("hickory_resolver=info".parse().unwrap())
            .add_directive("hickory_proto=warn".parse().unwrap())
            .add_directive("reqwest=warn".parse().unwrap());
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_android::layer("DohProxy").unwrap())
            .try_init();
    }

    #[cfg(not(target_os = "android"))]
    {
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};
        let _ = tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(false))
            .with(
                EnvFilter::from_default_env()
                    .add_directive("doh_proxy=info".parse().unwrap_or_default()),
            )
            .try_init();
    }
}
