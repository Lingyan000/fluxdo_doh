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

fn parse_required_string(ptr: *const c_char, field_name: &str) -> std::result::Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{} is null", field_name));
    }

    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) if !s.trim().is_empty() => Ok(s.to_string()),
        _ => Err(format!("invalid {}", field_name)),
    }
}

fn parse_optional_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(s) if !s.trim().is_empty() => Some(s.to_string()),
        _ => None,
    }
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

    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());

    let rt = get_runtime();
    let result = rt.block_on(async {
        let resolver = crate::dns::DnsResolver::shared(&doh_url, Some(&doh_url), false, None).await?;
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

/// Lookup IP addresses for a host via DOH A/AAAA records.
/// Returns a pointer to a JSON string:
/// {"ok":true,"data":["1.1.1.1","2606:4700:4700::1111"]} or {"ok":false,"error":"..."}
/// The caller must free the returned string with doh_proxy_free_string.
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_ip(
    host: *const c_char,
    doh_server: *const c_char,
    prefer_ipv6: c_int,
) -> *mut c_char {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());

    let rt = get_runtime();
    let result = rt.block_on(async {
        let resolver =
            crate::dns::DnsResolver::shared(&doh_url, Some(&doh_url), prefer_ipv6 != 0, None)
                .await?;
        resolver.lookup_ip(&host_str).await
    });

    match result {
        Ok(addrs) => {
            let json = serde_json::json!({
                "ok": true,
                "data": addrs
                    .into_iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>(),
            })
            .to_string();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Lookup a host in one round-trip and return IPs, ECH config and TTL.
/// Returns:
/// {"ok":true,"ips":["1.1.1.1"],"ech":"<base64|null>","ttl_secs":300}
#[no_mangle]
pub extern "C" fn doh_proxy_lookup_host(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
    force_refresh: c_int,
) -> *mut c_char {
    use base64::Engine;

    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => return error_json(&message),
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver = crate::dns::DnsResolver::shared(
            &doh_url,
            Some(effective_doh_url_ech),
            prefer_ipv6 != 0,
            None,
        )
        .await?;
        resolver.lookup_host(&host_str, force_refresh != 0).await
    });

    match result {
        Ok(lookup) => {
            let ech = lookup
                .ech_config
                .as_ref()
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()));
            let json = serde_json::json!({
                "ok": true,
                "ips": lookup
                    .addrs
                    .into_iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>(),
                "ech": ech,
                "preferred_ip": lookup.preferred_ip.map(|addr| addr.to_string()),
                "ttl_secs": lookup.ttl.as_secs(),
            })
            .to_string();
            match std::ffi::CString::new(json) {
                Ok(c) => c.into_raw(),
                Err(_) => error_json("CString conversion failed"),
            }
        }
        Err(e) => error_json(&format!("{}", e)),
    }
}

/// Record a successful host -> IP preference in the shared resolver.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn doh_proxy_record_host_success(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
    ip: *const c_char,
) -> c_int {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("record_host_success: {}", message);
            return 0;
        }
    };
    let ip_str = match parse_required_string(ip, "ip") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("record_host_success: {}", message);
            return 0;
        }
    };
    let ip_addr = match ip_str.parse::<std::net::IpAddr>() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!("record_host_success: invalid ip '{}': {}", ip_str, error);
            return 0;
        }
    };

    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver = crate::dns::DnsResolver::shared(
            &doh_url,
            Some(effective_doh_url_ech),
            prefer_ipv6 != 0,
            None,
        )
        .await?;
        resolver.record_host_success(&host_str, ip_addr);
        Ok::<(), crate::error::DohProxyError>(())
    });

    if let Err(error) = result {
        tracing::warn!("record_host_success failed for {} -> {}: {}", host_str, ip_str, error);
        0
    } else {
        1
    }
}

/// Clear the shared preferred IP for a host.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn doh_proxy_clear_preferred_host_ip(
    host: *const c_char,
    doh_server: *const c_char,
    doh_server_ech: *const c_char,
    prefer_ipv6: c_int,
) -> c_int {
    doh_proxy_init_logging();

    let host_str = match parse_required_string(host, "host") {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("clear_preferred_host_ip: {}", message);
            return 0;
        }
    };
    let doh_url = parse_optional_string(doh_server)
        .unwrap_or_else(|| "https://cloudflare-dns.com/dns-query".to_string());
    let doh_url_ech = parse_optional_string(doh_server_ech);

    let rt = get_runtime();
    let result = rt.block_on(async {
        let effective_doh_url_ech = doh_url_ech.as_deref().unwrap_or(doh_url.as_str());
        let resolver = crate::dns::DnsResolver::shared(
            &doh_url,
            Some(effective_doh_url_ech),
            prefer_ipv6 != 0,
            None,
        )
        .await?;
        resolver.clear_preferred_host_ip(&host_str);
        Ok::<(), crate::error::DohProxyError>(())
    });

    if let Err(error) = result {
        tracing::warn!("clear_preferred_host_ip failed for {}: {}", host_str, error);
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn doh_proxy_clear_dns_cache() -> c_int {
    doh_proxy_init_logging();

    let rt = get_runtime();
    rt.block_on(async {
        crate::dns::DnsResolver::clear_shared_caches().await;
    });
    1
}

/// Free a string returned by doh_proxy_lookup_ech_config / doh_proxy_lookup_ip / doh_proxy_lookup_host
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
