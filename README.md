# DOH Proxy

基于 Rust 实现的 DNS over HTTPS (DOH) 代理，内部支持 ECH (Encrypted Client Hello)。

## 功能

- **DOH DNS 解析**：通过 HTTPS 加密 DNS 查询，防止 DNS 污染
- **ECH 支持**：加密 TLS 握手中的 SNI 字段（需要服务器支持）
- **多 DOH 服务器**：支持 Cloudflare、Google、Quad9、DNSPod、腾讯 DNS、阿里 DNS
- **跨平台**：支持 Windows、macOS、Linux、Android、iOS

## 项目结构

```
rust/
├── Cargo.toml          # 项目配置
├── src/
│   ├── lib.rs          # 库入口
│   ├── main.rs         # 可执行文件入口（桌面平台）
│   ├── ffi.rs          # FFI 接口（移动平台）
│   ├── proxy.rs        # HTTP CONNECT 代理服务器
│   ├── dns.rs          # DOH DNS 解析器
│   ├── ech.rs          # TLS 连接器（ECH 支持）
│   └── error.rs        # 错误类型
└── README.md
```

## 编译

### 前置要求

- Rust 1.70+
- 对于 Android：cargo-ndk、Android NDK

### 桌面平台（Windows/macOS/Linux）

推荐使用一键脚本：

```bash
# Windows PowerShell
.\scripts\build_desktop.ps1

# macOS/Linux
./scripts/build_desktop.sh
```

或手动编译：

```bash
cd rust

# Debug 编译
cargo build

# Release 编译
cargo build --release

# 可执行文件位于
# Windows: target/release/doh_proxy_bin.exe
# macOS/Linux: target/release/doh_proxy_bin
```

### Android

推荐使用一键脚本（自动编译 + 复制到 jniLibs）：

```bash
# Windows PowerShell
.\scripts\build_android.ps1

# macOS/Linux/Git Bash
./scripts/build_android.sh
```

或手动编译：

```bash
# 安装 Android 目标
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# 安装 cargo-ndk
cargo install cargo-ndk

# 编译所有架构
cd rust
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 build --release

# 库文件位于
# target/aarch64-linux-android/release/libdoh_proxy.so
# target/armv7-linux-androideabi/release/libdoh_proxy.so
# target/x86_64-linux-android/release/libdoh_proxy.so
# target/i686-linux-android/release/libdoh_proxy.so
```

### iOS

```bash
# 安装 iOS 目标
rustup target add aarch64-apple-ios

cd rust
cargo build --release --target aarch64-apple-ios

# 静态库位于 target/aarch64-apple-ios/release/libdoh_proxy.a
```

## 运行（桌面平台）

```bash
# 默认配置（Cloudflare DOH，自动分配端口）
./target/release/doh_proxy_bin

# 指定端口
./target/release/doh_proxy_bin 8080

# 指定 DOH 服务器
./target/release/doh_proxy_bin 8080 --doh https://dns.alidns.com/dns-query

# 优先使用 IPv6
./target/release/doh_proxy_bin 8080 --ipv6
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `<port>` | 监听端口（0 = 自动分配） |
| `--doh <url>` | DOH 服务器 URL |
| `--ipv6` | 优先使用 IPv6 地址 |

### 支持的 DOH 服务器

| 名称 | URL |
|------|-----|
| Cloudflare | `https://cloudflare-dns.com/dns-query` |
| Google | `https://dns.google/dns-query` |
| Quad9 | `https://dns.quad9.net/dns-query` |
| DNSPod | `https://doh.pub/dns-query` |
| 腾讯 DNS | `https://dns.pub/dns-query` |
| 阿里 DNS | `https://dns.alidns.com/dns-query` |

## 测试

使用 curl 测试代理：

```bash
# 启动代理
./target/release/doh_proxy_bin 8080

# 使用代理访问网站
curl -x http://127.0.0.1:8080 https://example.com
```

## Flutter 集成

### Android

使用一键脚本编译并部署：

```bash
# Windows PowerShell
.\scripts\build_android.ps1

# macOS/Linux/Git Bash
./scripts/build_android.sh
```

脚本会自动编译所有架构并复制到 `android/app/src/main/jniLibs/`。

Flutter 中使用：

```dart
import 'package:fluxdo/services/network/doh_proxy/doh_proxy.dart';

// 启动代理
final service = DohProxyService.instance;
final success = await service.start(
  preferredPort: 0,  // 自动分配
  preferIPv6: false,
  dohServer: 'https://dns.alidns.com/dns-query',
);

if (success) {
  print('代理已启动，端口: ${service.port}');
}

// 停止代理
await service.stop();
```

### 桌面平台

桌面平台通过进程方式运行代理，需要将编译好的可执行文件放到正确位置：

- 开发时：`rust/target/release/doh_proxy_bin[.exe]`
- 打包后：与应用程序同目录

## FFI 接口

移动平台通过 FFI 调用 Rust 库：

```c
// 启动代理，返回端口号（-1 表示失败）
int doh_proxy_start(int port, int prefer_ipv6);

// 启动代理（指定 DOH 服务器）
int doh_proxy_start_with_server(int port, int prefer_ipv6, const char* doh_server);

// 停止代理
void doh_proxy_stop();

// 检查是否运行中（1 = 是，0 = 否）
int doh_proxy_is_running();

// 获取代理端口（0 = 未运行）
int doh_proxy_get_port();

// 初始化日志
void doh_proxy_init_logging();
```

## 架构说明

```
┌─────────────────────────────────────────────────────────────┐
│                      Flutter App                             │
├─────────────────────────────────────────────────────────────┤
│  DohProxyService (lib/services/network/doh_proxy/)          │
│    ├── 桌面平台：启动进程                                    │
│    └── 移动平台：FFI 调用                                    │
├─────────────────────────────────────────────────────────────┤
│                    Rust DOH Proxy                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ DohProxy    │  │ DnsResolver │  │ DohTls      │          │
│  │ Server      │──│ (DOH)       │──│ Connector   │          │
│  │ (CONNECT)   │  │             │  │ (ECH)       │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  DOH Server             │
              │  (Cloudflare/阿里/...)  │
              └─────────────────────────┘
```

## 工作原理

1. **HTTP CONNECT 代理**：客户端发送 `CONNECT host:port` 请求
2. **DOH DNS 解析**：通过加密 HTTPS 查询 DNS，获取目标 IP
3. **TCP 隧道**：建立到目标服务器的 TCP 连接
4. **双向转发**：在客户端和服务器之间转发数据
5. **ECH（可选）**：如果服务器支持，加密 TLS 握手中的 SNI

## 依赖

- rustls 0.23+ (TLS + ECH 支持)
- hickory-resolver (DOH + HTTPS 记录)
- tokio (异步运行时)

## License

MIT
