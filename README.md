# 🌐 XrayChecker

**多线程 V2Ray/Xray 代理检测工具**  
*快速、硬核、高效*

v1.0.0 版本

## ⚡ 工具介绍

**XrayChecker** — 一款基于 Python 开发的批量检测 V2Ray/Xray 代理可用性与延迟的工具。该脚本支持从文件或 URL（例如 GitHub Raw 链接）解析配置，解码 Base64（及其他格式），生成临时配置文件，并通过 Xray 核心程序进行真实可用性检测。

### 🔥 核心功能
*   **协议支持**：`VMess`、`VLESS`、`Trojan`、`Shadowsocks`、`Hysteria2`。
*   **智能解析**：可从杂乱文本、Base64 字符串、订阅链接中提取代理信息。
    - （简单说，不管你把链接写成啥样，脚本基本都能识别。）
*   **批量模式**：1 个 Xray 核心对应 1 批代理，批次内并行检测。最多支持 1337 个并发批次。
*   **运行模式**：美观的交互式菜单 / 命令行参数（CLI）两种方式。
*   **自动排序**：按延迟（ping）或速度自动排序可用代理。
*   **速度测试**：可选开启下载速度检测功能。
*   **丰富界面**：各类美观的加载动画与菜单交互。
*   **灵活配置**：包含大量可自定义参数的配置文件。
*   **调试留存**：核心程序崩溃时，自动保存 `batch*.json` 文件和日志到 `./failed_batches` 目录，并输出复现命令 `xray run -test -c ...`。
*   **解析自测**：快速测试解析功能（自动修复 `&amp;`、`&amp%3B`、`%26amp%3B` 等编码问题）。
*   **SS 安全过滤**：过滤含不支持加密方式的 Shadowsocks 链接（仅白名单 AEAD 系列），避免出现 `Exit: 23` 错误。
*   **REALITY 严格校验**：验证 `pbk`（base64url 格式 → 严格要求 32 字节）并标准化 `sid`（shortId 十六进制格式）。

---

## ⚠️ 重要：核心程序（Xray core）

脚本运行**必须**依赖 `xray`/`xray.exe` 核心程序（或兼容版本）。
若未安装核心程序，请从 `XTLS/Xray-core` 发布页下载对应系统的压缩包并解压到 `./bin` 目录。

### 🛠️ 手动安装
1. 进入 Xray-core 发布页：  
   👉 [**https://github.com/XTLS/Xray-core/releases**](https://github.com/XTLS/Xray-core/releases)
2. 下载对应系统/架构的压缩包（例如 `Xray-windows-64.zip`）。
3. 解压后将 `xray.exe` 放到脚本同级目录或 `./bin` 目录。

> 📂 推荐目录结构：
> - `v2rayChecker.py`
> - `bin/xray.exe` 或 `bin/xray`
> - `aggregator.py`（可选，用于 `--agg` 参数）

---

## 🚀 安装与运行

### 1. 克隆仓库
```bash
git clone https://github.com/limingda1212/XrayChecker
cd XrayChecker
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```
**请确保xray已经安装**

### 3. 运行
**交互式菜单模式：**
```bash
python v2rayChecker.py
```

**命令行模式（示例）：**
```bash
# 从文件检测代理
python v2rayChecker.py -f "proxies.txt"

# 从订阅链接检测
python v2rayChecker.py -u "https://example.com/sub"

# 指定线程数和超时时间
python v2rayChecker.py -f "list.txt" -T 50 -t 2
```

---

## ⚙️ config.json（关键配置项）

首次运行（或新增配置项）时会自动生成配置文件，关键项说明：

- `core_path`: 核心程序路径（可填 `"xray"` 或 `bin/xray`）。

---

## 🧪 解析自测
测试 URL 解析器是否能正确处理参数中的 HTML/URL 编码（`security/pbk/sid/flow/...` 等字段）。

```bash
python v2rayChecker.py --self-test
```

---

## 🐛 调试模式
调试专用模式：每批次仅检测 1 个代理，且仅启用 1 线程，快速定位“异常”链接/配置。

```bash
python v2rayChecker.py -f "proxies.txt" --debug
```

---

## 🧯 Xray 崩溃调试（Exit: 23）
若核心程序启动失败，脚本会将相关文件保存到 `./failed_batches` 目录，并输出复现命令 `xray run -test -c ...`。

---

## ⚙️ 命令行参数

| 参数 | 说明                                |
| :--- |:----------------------------------|
| `-m`, `--menu` | 强制启动交互式菜单                         |
| `-f`, `--file` | 代理文件路径（.txt 格式）                   |
| `-u`, `--url` | 订阅链接或代理列表 URL                     |
| `--agg` | 启动内置代理聚合器（抓取工具）                   |
| `--agg-cats` | 聚合器数据源分类（例如：`1 2`）                |
| `--agg-filter` | 聚合器关键词过滤（例如：`vless reality`）      |
| `-o`, `--output` | 可用代理保存文件（默认：`sortedProxy.txt`）    |
| `-T`, `--threads` | 并发核心程序（批次）数量上限                    |
| `-t`, `--timeout` | 响应超时时间（秒，默认：3）                    |
| `-l`, `--lport` | 核心程序起始本地端口（默认：1080）               |
| `-c`, `--core` | 核心程序可执行文件路径（xray/v2ray）           |
| `-d`, `--domain` | 连接测试域名（默认：Google/CF generate_204） |
| `-n`, `--number` | 限制检测代理数量（仅检测前 N 个）                |
| `--reuse` | 重新检测结果文件（`sortedProxy.txt`）中的代理   |
| `-s`, `--shuffle` | 检测前打乱代理列表                         |
| `--t2exec` | 核心程序启动等待时间（秒）                     |
| `--t2kill` | 终止核心进程后的延迟时间                      |
| `--speed` | 启用下载速度测试（替代仅检测延迟）                 |
| `--sort` | 结果排序方式：`ping`（延迟）或 `speed`（速度）    |
| `--speed-url` | 速度测试文件链接                          |
| `--self-test` | 运行 URL 解析自测                       |
| `--debug` | 调试模式（每批次 1 个代理，1 线程               |

---

### 📜 许可证

本项目采用 **MIT** 许可证。
