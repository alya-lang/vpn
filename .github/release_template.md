{{DESCRIPTION}}

## 💾 Pre-Built Binaries

Direct standalone executable packages are attached below for all supported operating systems:

| Platform | Architecture | Package Archive | Contents |
| :--- | :--- | :--- | :--- |
| 🪟 **Windows** | x86_64 | `alya-vpn-windows-x64.zip` | `alya-vpn.exe`, `config/` |
| 🐧 **Linux** | x86_64 | `alya-vpn-linux-x64.tar.gz` | `alya-vpn`, `config/` |
| 🍎 **macOS** | Apple Silicon (arm64) | `alya-vpn-macos-arm64.tar.gz` | `alya-vpn`, `config/` |

## 📦 Installation via Alya CLI

Using the Alya CLI:

```bash
alyac add {{PACKAGE_NAME}} --git https://github.com/{{REPOSITORY}} --tag {{TAG}}
alyac install
```

Or add it directly to your project's `alya.toml`:

```toml
[dependencies]
{{PACKAGE_NAME}} = { git = "https://github.com/{{REPOSITORY}}", tag = "{{TAG}}" }
```

## 🚀 What's Changed

{{CHANGELOG_COMMITS}}

## 🔗 Resources

- **Documentation**: [README.md](https://github.com/{{REPOSITORY}}#readme)
- **Examples**: [examples/](https://github.com/{{REPOSITORY}}/tree/{{TAG}}/examples)
- **Issue Tracker**: [GitHub Issues](https://github.com/{{REPOSITORY}}/issues)

---

{{FULL_CHANGELOG}}
