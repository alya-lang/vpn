# Module `logging`

Alya VPN - Log verbosity presets
A single "log_level" knob maps onto the individual per-category toggles
in main.alya (debug = everything chatty, error = errors only).

## Table of Contents

- [Enums](#enums)
  - [`LogLevel`](#enum-loglevel)
- [Functions](#functions)
  - [`parse_log_level`](#function-parse_log_level)

## Enums

### Enum `LogLevel`

| Variant | Explicit Value |
|:---|:---|
| `Debug` | `0` |
| `Info` | `1` |
| `Warn` | `2` |
| `Error` | `3` |

## Functions

### Function `parse_log_level`

```alya
function parse_log_level(s) -> LogLevel
```

Parses a log_level value (case-insensitive). Unknown values keep Info.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |

**Returns:** `LogLevel`
---

[↑ Workspace](../index.md)
