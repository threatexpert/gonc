import os
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
import zipfile

SCRIPT_DIR = Path(__file__).parent.resolve()
BIN_DIR = SCRIPT_DIR / "bin"
INDEX_HTML = BIN_DIR / "index.html"
NOTFOUND_HTML = BIN_DIR / "404.html"
HEADERS_FILE = BIN_DIR / "_headers"   # 放在根目录
BIN_ZIP = BIN_DIR / "bin.zip"

# ---------- 固定文案 ----------
HEADER_TEXT = """
<style>
body {
    font-family: sans-serif;
    font-size: 16px; /* 默认字体 */
    line-height: 1.5;
}

@media (max-width: 480px) {
    body {
        font-size: 18px; /* 小屏幕适当放大 */
    }
    .toggle-btn {
        font-size: 16px;
        padding: 6px 12px;
    }
}
/* 隐藏 checkbox */
#lang-toggle {
  display: none;
}

/* 右上角按钮 */
.toggle-btn {
  position: absolute;
  top: 0;
  right: 0;
  padding: 4px 10px;
  border: 1px solid #ccc;
  background: #f7f7f7;
  border-radius: 6px;
  cursor: pointer;
  font-family: sans-serif;
  font-size: 14px;
}
/* 默认显示中文，隐藏英文 */
.lang-zh {
    display: block;
    flex: 1;            /* 让内容块可伸缩 */
    min-width: 200px;   /* 手机屏幕时防止太窄 */
    font-size: 16px;    /* 默认字体大小，可适配手机 */
    line-height: 1.5;
}

.lang-en {
    display: none;
    flex: 1;
    min-width: 200px;
    font-size: 16px;
    line-height: 1.5;
}

/* 切换状态 */
#lang-toggle:checked ~ .content-wrapper .lang-zh {
    display: none;
}
#lang-toggle:checked ~ .content-wrapper .lang-en {
    display: block;
}

/* 手机屏幕适配 */
@media (max-width: 480px) {
    .lang-zh, .lang-en {
        font-size: 18px; /* 小屏幕放大字体 */
    }
}
</style>

<div style="font-family: sans-serif; margin-bottom: 20px; position: relative;">

    <h2 style="margin-bottom: 10px;">gonc $VERSION</h2>
    <p>Github: <a href="https://github.com/threatexpert/gonc">https://github.com/threatexpert/gonc</a></p>

    <!-- 语言切换按钮 -->
    <input type="checkbox" id="lang-toggle">
    <label for="lang-toggle" class="toggle-btn">Switch Language</label>

    <!-- 可切换内容 -->
    <div class="content-wrapper" style="
        display: flex; 
        gap: 20px; 
        margin-top: 20px; 
        flex-wrap: wrap;
    ">

        <!-- Chinese -->
        <div class="lang-zh" style="flex: 1; min-width: 280px;">
            <p><code>gonc</code> 是一个基于 Golang 的 <code>netcat</code> 工具，旨在更方便地建立点对点通信。</p>
            <h3>主要特点</h3>
            <ul>
            <li>
            <p>🔁 <strong>自动化内网穿透</strong>：零配置，双方仅需约定一个口令，使用参数<code>-p2p</code>既可自动发现彼此网络地址和穿透内网建立点对点连接，使用公共 STUN 和 MQTT 服务交换地址信息。</p>
            </li>
            <li>
            <p>🔒 <strong>端到端双向认证的加密</strong>：支持 TCP 的 TLS 和 UDP 的 DTLS 加密传输，可基于口令双向身份认证。</p>
            </li>
            <li>
            <p>🧩 <strong>灵活的服务配置</strong>：通过参数 <code>-e</code> 可灵活的设置为每个连接提供服务的应用程序，例如-e /bin/sh可提供远程cmdshell，还可以使用内置的虚拟命令便捷的使用socks5服务、http文件服务和流量转发功能。</p>
            </li>
            </ul>
        </div>

        <!-- English -->
        <div class="lang-en" style="flex: 1; min-width: 280px;">
            <p><code>gonc</code> is a Golang-based <code>netcat</code> tool designed to facilitate peer-to-peer communication.</p>
            <h3>Main Features</h3>
            <ul>
            <li>
            <p>🔁 <strong>Automated NAT Traversal</strong>: Zero configuration. Both sides only need to agree on a passphrase. By using the -p2p parameter, peers can automatically discover each other’s network addresses and establish a point-to-point connection through NAT traversal, leveraging public STUN and MQTT services for address exchange.</p>
            </li>
            <li>
            <p>🔒 <strong>End-to-End Encrypted with Mutual Authentication</strong>: Supports TLS for TCP and DTLS for UDP encrypted transmission, with passphrase-based mutual identity authentication.</p>
            </li>
            <li>
            <p>🧩 <strong>Flexible Service Configuration</strong>: With the -e parameter, you can flexibly set the application to serve each connection. For example, -e /bin/sh can provide a remote cmd shell. You can also use built-in virtual commands for convenient SOCKS5 service, HTTP file service, and traffic forwarding.</p>
            </li>
            </ul>
        </div>

    </div>
</div>
"""

# ---------- 计算 SHA-256 ----------
def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------- 人类可读文件大小 ----------
def human_size(num):
    for unit in ["B","KB","MB","GB"]:
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} TB"

# ---------- 获取 gonc.exe 的版本 ----------
def get_gonc_version():
    exe = BIN_DIR / "gonc.exe"
    if not exe.exists():
        return "unknown"

    try:
        p = subprocess.Popen(
            [str(exe)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        _, err = p.communicate(timeout=2)

        for line in err.splitlines():
            line = line.strip()
            if line.startswith("go-netcat"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("v"):
                    return parts[1]
        return "unknown"
    except Exception as e:
        return f"error: {e}"

def build_headers(files):
    """
    生成 Cloudflare Pages 专用的 _headers 文件，
    为每个 gonc二进制文件设置强制下载头。
    """
    lines = []

    for name, size, sha in files:
        lines.append(f"/{name}")
        lines.append("  Content-Type: application/octet-stream")
        lines.append(f'  Content-Disposition: attachment; filename="{name}"')
        lines.append("")  # 空行分隔

    HEADERS_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"✔ 已生成 {HEADERS_FILE}")

def build_zip(files_to_zip):
    """
    files_to_zip: list of Path 对象
    将指定文件打包成 bin.zip，如果已存在先删除
    """
    # 如果 bin.zip 已存在，先删除
    if BIN_ZIP.exists():
        print(f"⚠ {BIN_ZIP} 已存在，删除...")
        BIN_ZIP.unlink()

    print(f"⚠ {BIN_ZIP} 打包中({len(files_to_zip)}个文件)..." )

    # 打包指定文件
    with zipfile.ZipFile(BIN_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for f in files_to_zip:
            if f.is_file():
                zipf.write(f, arcname=f.name)  # 保持文件名，不带目录
    print(f"✔ 已生成 {BIN_ZIP}")

# ---------- 生成 index.html ----------
def build_index():
    files = []

    for f in BIN_DIR.iterdir():
        if f.is_file() and f.name.startswith("gonc"):
            sha = sha256_of_file(f)
            size = human_size(f.stat().st_size)
            files.append((f.name, size, sha))

    version = get_gonc_version()
    if not version.startswith("v"):
        raise Exception("无法获取 gonc 版本号")
    print(f"✔ 当前版本 {version}")

    html = []
    html.append("<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>gonc - Netcat with automated NAT traversal, secure P2P, and advanced features for shell access, file transfer, and network proxying.</title></head><body>")
    html.append(HEADER_TEXT.replace("$VERSION", version))
    html.append("<hr>")

    html.append("<table border='1' cellpadding='6' cellspacing='0'>")
    html.append("<tr><th>文件名/Filename</th><th>大小/Size</th><th>SHA-256</th></tr>")

    for name, size, sha in files:
        html.append(
            f"<tr>"
            f"<td><a href='./{name}' download='{name}'>{name}</a></td>"
            f"<td>{size}</td>"
            f"<td><code>{sha}</code></td>"
            f"</tr>"
        )

    html.append("</table>")
    html.append("</body></html>")

    INDEX_HTML.write_text("\n".join(html), encoding="utf-8")
    print(f"✔ 已生成 {INDEX_HTML}")
    NOTFOUND_HTML.write_text("<h1>404 Not Found</h1><p>The file you requested does not exist.</p>", encoding="utf-8")
    print(f"✔ 已生成 {NOTFOUND_HTML}")
    build_headers(files)

    file_paths = [INDEX_HTML, NOTFOUND_HTML] + [BIN_DIR / name for name, size, sha in files]
    build_zip(file_paths)

if __name__ == "__main__":
    build_index()
