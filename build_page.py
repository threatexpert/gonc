import os
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
import zipfile
import shutil

SCRIPT_DIR = Path(__file__).parent.resolve()
BIN_DIR = SCRIPT_DIR / "bin"
SITE_DIR = SCRIPT_DIR / "site" 

INDEX_HTML = BIN_DIR / "index.html"
NOTFOUND_HTML = BIN_DIR / "404.html"
#HEADERS_FILE = BIN_DIR / "_headers"
REDIRECTS_FILE = BIN_DIR / "_redirects"
R2STORAGE_URL_BASE = "https://gonc.download"
GUI_REDIRECTS = [
    ("/gui/windows-amd64.zip", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-windows-amd64.zip"),
    ("/gui/windows-arm64.zip", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-windows-arm64.zip"),
    ("/gui/ubuntu-amd64.tar.gz", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-ubuntu-amd64.tar.gz"),
    ("/gui/macos-amd64.zip", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-macos-amd64.zip"),
    ("/gui/macos-arm64.zip", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-macos-arm64.zip"),
    ("/gui/android-arm64.apk", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/gonc-gui-android-arm64.apk"),
    ("/gui/manifest.json", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/manifest.json"),
    ("/gui/version.txt", f"{R2STORAGE_URL_BASE}/gonc-gui/latest/version.txt"),
]

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
    display: none;
    flex: 1;            /* 让内容块可伸缩 */
    min-width: 200px;   /* 手机屏幕时防止太窄 */
    font-size: 16px;    /* 默认字体大小，可适配手机 */
    line-height: 1.5;
}

.lang-en {
    display: block;
    flex: 1;
    min-width: 200px;
    font-size: 16px;
    line-height: 1.5;
}

/* 切换状态 */
#lang-toggle:checked ~ .content-wrapper .lang-zh {
    display: block;
}
#lang-toggle:checked ~ .content-wrapper .lang-en {
    display: none;
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
    <p>Github: <a href="https://github.com/threatexpert/gonc">https://github.com/threatexpert/gonc</a>
    <br><a href="/docs/">Docs/详细文档</a></br>
    </p>

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
            <h3>相关项目</h3>
            <ul>
            <li><a href="https://github.com/threatexpert/gonc-gui">gonc-gui</a> —— 基于 <code>gonc</code> 的桌面（Windows）和 Android 应用：提供便捷的跨设备、跨网络点对点直连与安全文件传输，只需分享口令（或扫码），无需命令行。
                <div style="margin-top: 6px;">
                    Download:
                    <a href="/gui/windows-amd64.zip">Windows x64</a> |
                    <a href="/gui/windows-arm64.zip">Windows ARM64</a> |
                    <a href="/gui/macos-arm64.zip">macOS Apple Silicon</a> |
                    <a href="/gui/android-arm64.apk">Android APK</a>
                </div>
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
            <h3>Related Projects</h3>
            <ul>
            <li><a href="https://github.com/threatexpert/gonc-gui">gonc-gui</a> — a desktop (Windows) and Android app built on <code>gonc</code>: convenient cross-device, cross-network P2P direct connection and secure file transfer, just share a passphrase (or scan a QR code), no command line required.
                <div style="margin-top: 6px;">
                    Download:
                    <a href="/gui/windows-amd64.zip">Windows x64</a> |
                    <a href="/gui/windows-arm64.zip">Windows ARM64</a> |
                    <a href="/gui/macos-arm64.zip">macOS Apple Silicon</a> |
                    <a href="/gui/android-arm64.apk">Android APK</a>
                </div>
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
    for key in ("GONC_VERSION", "GITHUB_REF_NAME"):
        version = os.environ.get(key, "").strip()
        if version.startswith("v"):
            return version

    github_ref = os.environ.get("GITHUB_REF", "").strip()
    if github_ref.startswith("refs/tags/v"):
        return github_ref.removeprefix("refs/tags/")

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

    #HEADERS_FILE.write_text("\n".join(lines), encoding="utf-8")
    #print(f"✔ 已生成 {HEADERS_FILE}")

def build_zip(files_to_zip, zip_name):
    """
    files_to_zip: list of Path 对象 (index.html, 404.html, _redirects)
    zip_name: 输出 zip 文件名
    功能：
    1. 将 files_to_zip 打包到 zip 根目录
    2. 将 SITE_DIR 目录下的所有文件打包到 zip 的 docs/ 目录下
    """
    DEPLOY_ZIP = BIN_DIR / zip_name
    
    # 如果 .zip 已存在，先删除
    if DEPLOY_ZIP.exists():
        print(f"⚠ {DEPLOY_ZIP} 已存在，删除...")
        DEPLOY_ZIP.unlink()

    print(f"📦 开始打包 {DEPLOY_ZIP} ...")

    with zipfile.ZipFile(DEPLOY_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        # 1. 打包指定文件 (index.html, 404.html 等) 到 Zip 根目录
        for f in files_to_zip:
            if f.is_file():
                print(f"  + 添加文件: {f.name}")
                zipf.write(f, arcname=f.name)
        
        # 2. 打包 site 目录内容到 Zip 的 docs/ 目录
        if SITE_DIR.exists() and SITE_DIR.is_dir():
            print(f"  + 添加目录: {SITE_DIR} -> docs/")
            count = 0
            # 使用 rglob 递归遍历所有文件
            for file_path in SITE_DIR.rglob("*"):
                if file_path.is_file():
                    # 计算相对路径，例如 site/css/style.css -> css/style.css
                    rel_path = file_path.relative_to(SITE_DIR)
                    # 拼接目标路径 docs/css/style.css
                    target_path = Path("docs") / rel_path
                    zipf.write(file_path, arcname=str(target_path))
                    count += 1
            print(f"  ✔ 已打包 site 目录 ({count} 个文件)")
        else:
            print(f"  ⚠ 警告: 未找到 site 目录 ({SITE_DIR})，跳过打包文档。")

    print(f"✔ 成功生成 {DEPLOY_ZIP}")

def build_redirects(files, version):
    """
    生成 Cloudflare Pages 用的 _redirects 文件，
    将所有 gonc 二进制文件重定向到 R2 存储路径。
    """
    lines = []

    for name, size, sha in files:
        target = f"{R2STORAGE_URL_BASE}/{version}/{name}"
        lines.append(f"/{name}    {target}    302")

    for path, target in GUI_REDIRECTS:
        lines.append(f"{path}    {target}    302")

    REDIRECTS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"✔ 已生成 {REDIRECTS_FILE}")


def build_pages():
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
            f"<td><a href='{name}' download='{name}'>{name}</a></td>"
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
    build_redirects(files, version)

    file_paths = [
        INDEX_HTML,
        NOTFOUND_HTML,
        # HEADERS_FILE, 
        REDIRECTS_FILE
    ]
    os.makedirs(BIN_DIR / version, exist_ok=True)
    for name, size, sha in files:
        shutil.copy2((BIN_DIR / name), (BIN_DIR / version / name))
        if sha != sha256_of_file(BIN_DIR / version / name):
            raise Exception(f"复制文件校验失败: {name}")
    shutil.copy2(INDEX_HTML, (BIN_DIR / version / "index.html"))

    build_zip(file_paths, f"deploy_{version}.zip")
    for f in file_paths:
        os.remove(f)

if __name__ == "__main__":
    build_pages()
