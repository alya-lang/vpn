Alya VPN is a high-performance, secure, per-application split-tunneling VPN client & server built with the [Alya Programming Language](https://github.com/alya-lang/alya).

## 🚀 What's Changed

{{CHANGELOG_COMMITS}}

## 📦 Pre-built Binaries

| Platform | Architecture | Package | Checksum |
|:---|:---|:---|:---:|
| <img src="https://svgl.app/library/linux.svg" width="16" height="16" valign="middle" alt="Linux" />&nbsp;**Linux** | `x86_64` | [alya-vpn-{{VERSION}}-x86_64-linux.tar.gz]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-linux.tar.gz) | [`{{LINUX_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-linux.tar.gz.sha256) |
| <img src="https://svgl.app/library/linux.svg" width="16" height="16" valign="middle" alt="Linux" />&nbsp;**Linux** | `arm64` | [alya-vpn-{{VERSION}}-arm64-linux.tar.gz]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-linux.tar.gz) | [`{{LINUX_ARM_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-linux.tar.gz.sha256) |
| <picture><source media="(prefers-color-scheme: dark)" srcset="https://svgl.app/library/apple_dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://svgl.app/library/apple.svg"><img src="https://svgl.app/library/apple.svg" width="16" height="16" valign="middle" alt="macOS" /></picture>&nbsp;**macOS** | `arm64` (Apple Silicon) | [alya-vpn-{{VERSION}}-arm64-macos.tar.gz]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-macos.tar.gz) | [`{{MAC_ARM_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-macos.tar.gz.sha256) |
| <picture><source media="(prefers-color-scheme: dark)" srcset="https://svgl.app/library/apple_dark.svg"><source media="(prefers-color-scheme: light)" srcset="https://svgl.app/library/apple.svg"><img src="https://svgl.app/library/apple.svg" width="16" height="16" valign="middle" alt="macOS" /></picture>&nbsp;**macOS** | `x86_64` (Intel) | [alya-vpn-{{VERSION}}-x86_64-macos.tar.gz]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-macos.tar.gz) | [`{{MAC_X64_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-macos.tar.gz.sha256) |
| <img src="https://svgl.app/library/windows.svg" width="16" height="16" valign="middle" alt="Windows" />&nbsp;**Windows** | `x86_64` | [alya-vpn-{{VERSION}}-x86_64-windows.zip]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-windows.zip) | [`{{WIN_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-x86_64-windows.zip.sha256) |
| <img src="https://svgl.app/library/windows.svg" width="16" height="16" valign="middle" alt="Windows" />&nbsp;**Windows** | `arm64` | [alya-vpn-{{VERSION}}-arm64-windows.zip]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-windows.zip) | [`{{WIN_ARM_SHA_SHORT}}`]({{REPO_URL}}/releases/download/{{VERSION}}/alya-vpn-{{VERSION}}-arm64-windows.zip.sha256) |

### 🔒 SHA-256 Checksums

```text
{{LINUX_SHA}}  alya-vpn-{{VERSION}}-x86_64-linux.tar.gz
{{LINUX_ARM_SHA}}  alya-vpn-{{VERSION}}-arm64-linux.tar.gz
{{MAC_ARM_SHA}}  alya-vpn-{{VERSION}}-arm64-macos.tar.gz
{{MAC_X64_SHA}}  alya-vpn-{{VERSION}}-x86_64-macos.tar.gz
{{WIN_SHA}}  alya-vpn-{{VERSION}}-x86_64-windows.zip
{{WIN_ARM_SHA}}  alya-vpn-{{VERSION}}-arm64-windows.zip
```

---

## ⚡ Quick Start

### Linux / macOS
```bash
# 1. Extract the archive
tar -xzf alya-vpn-{{VERSION}}-<platform>.tar.gz
cd alya-vpn-{{VERSION}}-<platform>

# 2. Check executable
./alya-vpn --version

# 3. Start local VPN Client (SOCKS5 proxy at 127.0.0.1:1080)
./alya-vpn client --config config/client.toml

# Or run headless VPN Server on VPS:
./alya-vpn server --config config/server.toml
```

### Windows (PowerShell)
```powershell
# 1. Extract the archive
Expand-Archive alya-vpn-{{VERSION}}-x86_64-windows.zip
cd alya-vpn-{{VERSION}}-x86_64-windows

# 2. Check executable
.\alya-vpn.exe --version

# 3. Start local VPN Client (SOCKS5 proxy at 127.0.0.1:1080)
.\alya-vpn.exe client --config config\client.toml

# Or run headless VPN Server:
.\alya-vpn.exe server --config config\server.toml
```

---

## 🔒 Checksum Verification

```bash
# Linux / macOS
shasum -a 256 -c alya-vpn-{{VERSION}}-<platform>.tar.gz.sha256

# Windows (PowerShell)
(Get-FileHash alya-vpn-{{VERSION}}-x86_64-windows.zip -Algorithm SHA256).Hash.ToLower()
```

---

## 🔗 Useful Links

- **Documentation**: [README.md]({{REPO_URL}}#readme)
- **Architecture Overview**: [Architecture]({{REPO_URL}}#architecture-overview)
- **Split-Tunneling Modes**: [Configuration Guide]({{REPO_URL}}#split-tunneling-modes)
- **Issue Tracker**: [GitHub Issues]({{REPO_URL}}/issues)

---

{{FULL_CHANGELOG}}
