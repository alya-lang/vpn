# Module `router`

Alya VPN - Split Tunneling Router
Evaluates routing decisions per-application (Include vs Exclude modes)

## Table of Contents

- [Functions](#functions)
  - [`mode_all`](#function-mode_all)
  - [`mode_include`](#function-mode_include)
  - [`mode_exclude`](#function-mode_exclude)
  - [`pattern_match`](#function-pattern_match)
  - [`process_matches_any`](#function-process_matches_any)
  - [`should_route_through_vpn`](#function-should_route_through_vpn)
  - [`parse_split_mode`](#function-parse_split_mode)

## Functions

### Function `mode_all`

```alya
function mode_all()
```

Split Tunneling Modes

### Function `mode_include`

```alya
function mode_include()
```

### Function `mode_exclude`

```alya
function mode_exclude()
```

### Function `pattern_match`

```alya
function pattern_match(pattern, text)
```

Checks if target string matches pattern with optional leading/trailing wildcard '*'

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `pattern` | `auto` | `-` |
| `text` | `auto` | `-` |

### Function `process_matches_any`

```alya
function process_matches_any(app_list, proc_name)
```

Checks if a process name matches any pattern in the list

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `app_list` | `auto` | `-` |
| `proc_name` | `auto` | `-` |

### Function `should_route_through_vpn`

```alya
function should_route_through_vpn(mode, app_list, proc_name)
```

Evaluates whether traffic from a specific process should route through the VPN
Returns 1 (route via VPN tunnel) or 0 (direct connection / bypass VPN)

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `mode` | `auto` | `-` |
| `app_list` | `auto` | `-` |
| `proc_name` | `auto` | `-` |

### Function `parse_split_mode`

```alya
function parse_split_mode(s, default_mode)
```

Parses a split-tunnel mode config value ("all" / "inc[lude]" / "exc[lude]",
case-insensitive). Unknown values keep the caller-provided default instead
of silently changing behavior.

**Parameters:**

| Parameter | Type | Default |
|:---|:---|:---|
| `s` | `auto` | `-` |
| `default_mode` | `auto` | `-` |
---

[← All modules](index.md) · [↑ Workspace](../index.md)
