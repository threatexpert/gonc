import hashlib
import html
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
BIN_DIR = SCRIPT_DIR / "bin"
SITE_DIR = SCRIPT_DIR / "site"

INDEX_HTML = BIN_DIR / "index.html"
NOTFOUND_HTML = BIN_DIR / "404.html"
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

PAGE_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="gonc is a peer-to-peer networking tool with automated NAT traversal, encrypted transport, file transfer, proxying, and remote service support.">
<title>gonc - Secure P2P networking and file transfer</title>
<style>
:root {
    color-scheme: light;
    --bg: #f6f8fb;
    --panel: #ffffff;
    --panel-soft: #eef7f4;
    --text: #172033;
    --muted: #5f6b7a;
    --line: #dce5ee;
    --accent: #0f766e;
    --accent-strong: #115e59;
    --accent-warm: #c2410c;
    --shadow: 0 18px 55px rgba(23, 32, 51, 0.08);
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    min-width: 320px;
    background:
        linear-gradient(180deg, rgba(15, 118, 110, 0.08), rgba(255, 255, 255, 0) 420px),
        var(--bg);
    color: var(--text);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", "Helvetica Neue", Arial, sans-serif;
    font-size: 16px;
    line-height: 1.65;
}

a {
    color: var(--accent-strong);
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

code {
    border: 1px solid rgba(15, 118, 110, 0.18);
    border-radius: 6px;
    background: rgba(15, 118, 110, 0.08);
    color: #0f4f4a;
    padding: 0.1rem 0.35rem;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 0.92em;
}

#lang-toggle {
    position: absolute;
    opacity: 0;
    pointer-events: none;
}

.page-shell {
    width: min(1160px, calc(100% - 40px));
    margin: 0 auto;
}

.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
    padding: 22px 0;
}

.brand {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: var(--text);
    font-weight: 750;
    letter-spacing: 0;
}

.brand-mark {
    display: grid;
    width: 34px;
    height: 34px;
    place-items: center;
    border-radius: 8px;
    background: var(--accent);
    color: #fff;
    font-size: 18px;
}

.nav-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    justify-content: flex-end;
}

.nav-link,
.lang-switch,
.button {
    display: inline-flex;
    min-height: 40px;
    align-items: center;
    justify-content: center;
    border-radius: 8px;
    border: 1px solid var(--line);
    background: rgba(255, 255, 255, 0.72);
    color: var(--text);
    padding: 0 14px;
    font-weight: 650;
    text-decoration: none;
    white-space: nowrap;
}

.nav-link:hover,
.lang-switch:hover,
.button:hover {
    border-color: rgba(15, 118, 110, 0.38);
    text-decoration: none;
}

.lang-switch {
    cursor: pointer;
}

.label-en,
.lang-en {
    display: none !important;
}

#lang-toggle:checked ~ .page-shell .lang-zh,
#lang-toggle:checked ~ .page-shell .label-zh {
    display: none !important;
}

#lang-toggle:checked ~ .page-shell .label-en {
    display: inline !important;
}

#lang-toggle:checked ~ .page-shell div.lang-en,
#lang-toggle:checked ~ .page-shell section.lang-en,
#lang-toggle:checked ~ .page-shell p.lang-en,
#lang-toggle:checked ~ .page-shell h2.lang-en {
    display: block !important;
}

#lang-toggle:checked ~ .page-shell ul.lang-en {
    display: grid !important;
}

#lang-toggle:checked ~ .page-shell span.lang-en {
    display: inline !important;
}

.hero {
    display: grid;
    grid-template-columns: minmax(0, 1.14fr) minmax(320px, 0.86fr);
    gap: 34px;
    align-items: center;
    min-height: 510px;
    padding: 36px 0 52px;
}

h1 {
    max-width: 760px;
    margin: 0;
    color: #111827;
    font-size: clamp(1.8rem, 3vw, 3rem);
    line-height: 1.12;
    letter-spacing: 0;
}

.version-badge {
    display: inline-flex;
    align-items: center;
    min-height: 24px;
    margin-left: 2px;
    border: 1px solid var(--line);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.78);
    color: var(--muted);
    padding: 0 8px;
    font-size: 0.78rem;
    font-weight: 750;
}

.lead {
    max-width: 680px;
    margin: 24px 0 0;
    color: var(--muted);
    font-size: 1.18rem;
}

.hero-actions {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-top: 30px;
}

.button-primary {
    border-color: var(--accent);
    background: var(--accent);
    color: #fff;
    box-shadow: 0 14px 34px rgba(15, 118, 110, 0.2);
}

.button-primary:hover {
    border-color: var(--accent-strong);
    background: var(--accent-strong);
    color: #fff;
}

.hero-panel {
    border: 1px solid rgba(15, 118, 110, 0.16);
    border-radius: 8px;
    background: var(--panel);
    box-shadow: var(--shadow);
    overflow: hidden;
}

.panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 18px 20px;
    border-bottom: 1px solid var(--line);
    background: var(--panel-soft);
}

.panel-title {
    margin: 0;
    font-size: 1rem;
    font-weight: 800;
}

.scenario-list {
    display: grid;
    gap: 0;
    margin: 0;
    padding: 0;
    list-style: none;
}

.scenario-list li {
    display: grid;
    grid-template-columns: 34px minmax(0, 1fr);
    gap: 14px;
    padding: 19px 20px;
    border-bottom: 1px solid var(--line);
}

.scenario-list li:last-child {
    border-bottom: 0;
}

.scenario-icon {
    display: grid;
    width: 34px;
    height: 34px;
    place-items: center;
    border-radius: 8px;
    background: #f1f5f9;
    color: var(--accent-strong);
    font-weight: 850;
}

.scenario-list h3 {
    margin: 0;
    font-size: 1rem;
}

.scenario-list p {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 0.95rem;
}

.gui-band {
    padding: 12px 0 44px;
}

.section-kicker {
    margin: 0 0 8px;
    color: var(--accent-warm);
    font-size: 0.82rem;
    font-weight: 850;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

.section-kicker-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    margin-bottom: 8px;
}

.section-kicker-row .section-kicker {
    margin: 0;
}

.section-kicker-row .button {
    min-height: 34px;
    padding: 0 12px;
}

.gui-band h2,
.downloads h2 {
    margin: 0;
    color: #111827;
    font-size: 1.75rem;
    line-height: 1.18;
}

.gui-band p,
.downloads-note {
    margin: 12px 0 0;
    color: var(--muted);
}

.gui-downloads {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px 12px;
    margin-top: 16px;
    color: var(--muted);
    font-size: 0.94rem;
}

.gui-download-label {
    font-weight: 750;
    color: var(--muted);
}

.gui-downloads a {
    display: inline-flex;
    align-items: center;
    min-height: 30px;
    border: 1px solid var(--line);
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.74);
    padding: 0 10px;
    font-weight: 700;
}

.gui-downloads a:hover {
    text-decoration: none;
    border-color: rgba(15, 118, 110, 0.38);
}

.downloads {
    padding: 12px 0 64px;
}

.download-head {
    display: flex;
    align-items: end;
    justify-content: space-between;
    gap: 24px;
    margin-bottom: 18px;
}

.download-copy {
    flex: 1;
    min-width: 0;
}

.table-wrap {
    overflow-x: auto;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel);
    box-shadow: 0 10px 34px rgba(23, 32, 51, 0.06);
}

.download-table {
    width: 100%;
    border-collapse: collapse;
    min-width: 760px;
}

.download-table th,
.download-table td {
    padding: 15px 18px;
    border-bottom: 1px solid var(--line);
    text-align: left;
    vertical-align: top;
}

.download-table th {
    background: #f8fafc;
    color: #4b5563;
    font-size: 0.78rem;
    font-weight: 850;
    letter-spacing: 0.07em;
    text-transform: uppercase;
}

.download-table tr:last-child td {
    border-bottom: 0;
}

.file-link {
    font-weight: 800;
}

.sha {
    display: block;
    max-width: 560px;
    overflow-wrap: anywhere;
    color: #334155;
    font-size: 0.78rem;
}

.empty-state {
    padding: 24px;
    color: var(--muted);
}

@media (max-width: 860px) {
    .hero {
        grid-template-columns: 1fr;
    }

    .hero {
        min-height: auto;
        padding-top: 18px;
    }

    .download-head {
        display: block;
    }
}

@media (max-width: 560px) {
    .page-shell {
        width: min(100% - 28px, 1160px);
    }

    .topbar {
        align-items: flex-start;
        flex-direction: column;
    }

    .nav-actions {
        width: 100%;
        justify-content: flex-start;
    }

    .nav-link,
    .lang-switch,
    .button {
        min-height: 42px;
    }

    h1 {
        font-size: 1.86rem;
    }

    .lead {
        font-size: 1.05rem;
    }

}
</style>
</head>
<body>
<input type="checkbox" id="lang-toggle">
<script>
(function () {
    var toggle = document.getElementById("lang-toggle");
    var languages = navigator.languages && navigator.languages.length
        ? navigator.languages
        : [navigator.language || navigator.userLanguage || ""];
    var wantsChinese = languages.some(function (lang) {
        return /^zh\\b/i.test(lang);
    });

    toggle.checked = !wantsChinese;
    document.documentElement.lang = wantsChinese ? "zh-CN" : "en";
})();
</script>
<div class="page-shell">
    <header class="topbar">
        <a class="brand" href="/">
            <span class="brand-mark">g</span>
            <span>gonc</span>
            <span class="version-badge">$VERSION</span>
        </a>
        <nav class="nav-actions" aria-label="Primary">
            <a class="nav-link" href="https://github.com/threatexpert/gonc">GitHub</a>
            <a class="nav-link" href="/docs/">Docs</a>
            <label class="lang-switch" for="lang-toggle">
                <span class="label-zh">English</span>
                <span class="label-en">中文</span>
            </label>
        </nav>
    </header>

    <main>
        <section class="hero">
            <div>
                <div class="lang-zh">
                    <h1>让两台设备，更容易安全直连。</h1>
                    <p class="lead">gonc 是一个面向点对点通信的网络工具，支持自动 NAT 穿透、端到端加密、文件传输、代理和远程服务。需要命令行时它足够强，也可以配合 GUI 更轻松地使用。</p>
                    <div class="hero-actions">
                        <a class="button button-primary" href="#gui">下载图形界面</a>
                        <a class="button" href="#downloads">下载命令行版</a>
                    </div>
                </div>
                <div class="lang-en">
                    <h1>Secure direct connections, with less friction.</h1>
                    <p class="lead">gonc is a peer-to-peer networking tool with automated NAT traversal, end-to-end encryption, file transfer, proxying, and remote service support. Use it from the command line or pair it with the GUI for a simpler workflow.</p>
                    <div class="hero-actions">
                        <a class="button button-primary" href="#gui">Download GUI</a>
                        <a class="button" href="#downloads">Command-line builds</a>
                    </div>
                </div>
            </div>

            <aside class="hero-panel" aria-label="Highlights">
                <div class="panel-head">
                    <p class="panel-title lang-zh">核心能力</p>
                    <p class="panel-title lang-en">Highlights</p>
                </div>
                <ul class="scenario-list lang-zh">
                    <li>
                        <span class="scenario-icon">1</span>
                        <div>
                            <h3>自动穿透内网</h3>
                            <p>双方只需约定口令，使用公共 STUN 和 MQTT 服务<strong>加密</strong>交换地址信息。</p>
                        </div>
                    </li>
                    <li>
                        <span class="scenario-icon">2</span>
                        <div>
                            <h3>端到端加密</h3>
                            <p>基于 TLS 1.3 建立安全连接，自动从口令派生 TLS 证书，并强制双向身份认证。</p>
                        </div>
                    </li>
                    <li>
                        <span class="scenario-icon">3</span>
                        <div>
                            <h3>连接后能做更多</h3>
                            <p>可用于安全文件服务、SOCKS5 / HTTP 代理、端口转发和远程服务。</p>
                        </div>
                    </li>
                </ul>
                <ul class="scenario-list lang-en">
                    <li>
                        <span class="scenario-icon">1</span>
                        <div>
                            <h3>Automated NAT traversal</h3>
                            <p>Peers only need to agree on a passphrase, then use public STUN and MQTT services to exchange address information in an <strong>encrypted</strong> way.</p>
                        </div>
                    </li>
                    <li>
                        <span class="scenario-icon">2</span>
                        <div>
                            <h3>End-to-end encryption</h3>
                            <p>Establishes a secure connection with TLS 1.3, automatically derives TLS certificates from the passphrase, and enforces mutual authentication.</p>
                        </div>
                    </li>
                    <li>
                        <span class="scenario-icon">3</span>
                        <div>
                            <h3>More than a connection</h3>
                            <p>Use it for secure file service, SOCKS5 / HTTP proxying, port forwarding, and remote services.</p>
                        </div>
                    </li>
                </ul>
            </aside>
        </section>

        <section class="gui-band" id="gui">
            <div class="download-head">
                <div class="download-copy">
                    <div class="section-kicker-row">
                        <p class="section-kicker">GONC-GUI</p>
                        <a class="button" href="https://github.com/threatexpert/gonc-gui">Github</a>
                    </div>
                    <h2 class="lang-zh">多平台图形界面应用，更方便地连接、传输文件和组网。</h2>
                    <h2 class="lang-en">A cross-platform GUI app for connection, file transfer, and networking.</h2>
                    <p class="lang-zh">gonc-gui 基于 gonc，支持在不同平台系统上通过图形界面建立安全连接，进行文件传输，并组织跨设备、跨网络的点对点网络。</p>
                    <p class="lang-en">gonc-gui is built on gonc and provides a graphical app across platforms for secure connections, file transfer, and cross-device peer-to-peer networking.</p>
                    <div class="gui-downloads" aria-label="GUI downloads">
                        <span class="gui-download-label lang-zh">下载</span>
                        <span class="gui-download-label lang-en">Downloads</span>
                        <a href="/gui/windows-amd64.zip">Windows x64</a>
                        <a href="/gui/windows-arm64.zip">Windows ARM64</a>
                        <a href="/gui/macos-arm64.zip">macOS Apple Silicon</a>
                        <a href="/gui/android-arm64.apk">Android APK</a>
                    </div>
                </div>
            </div>
        </section>

        <section class="downloads" id="downloads">
            <div class="download-head">
                <div>
                    <p class="section-kicker">Downloads</p>
                    <h2 class="lang-zh">命令行版本</h2>
                    <h2 class="lang-en">Command-line builds</h2>
                    <p class="downloads-note lang-zh">请选择与你的系统匹配的文件。</p>
                    <p class="downloads-note lang-en">Choose the build that matches your system.</p>
                </div>
                <a class="button" href="/docs/">Docs / 详细文档</a>
            </div>
            <div class="table-wrap">
                $DOWNLOAD_TABLE
            </div>
        </section>
    </main>
</div>
</body>
</html>
"""


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(num):
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024:
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} TB"


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
            text=True,
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
    lines = []

    for name, _, _ in files:
        lines.append(f"/{name}")
        lines.append("  Content-Type: application/octet-stream")
        lines.append(f'  Content-Disposition: attachment; filename="{name}"')
        lines.append("")

    # Cloudflare Pages _headers can be enabled here if attachment headers are needed.
    # HEADERS_FILE.write_text("\n".join(lines), encoding="utf-8")


def build_zip(files_to_zip, zip_name):
    deploy_zip = BIN_DIR / zip_name

    if deploy_zip.exists():
        print(f"Removing existing {deploy_zip} ...")
        deploy_zip.unlink()

    print(f"Building {deploy_zip} ...")

    with zipfile.ZipFile(deploy_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for f in files_to_zip:
            if f.is_file():
                print(f"  + file: {f.name}")
                zipf.write(f, arcname=f.name)

        if SITE_DIR.exists() and SITE_DIR.is_dir():
            print(f"  + docs: {SITE_DIR} -> docs/")
            count = 0
            for file_path in SITE_DIR.rglob("*"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(SITE_DIR)
                    target_path = Path("docs") / rel_path
                    zipf.write(file_path, arcname=str(target_path))
                    count += 1
            print(f"  packed docs ({count} files)")
        else:
            print(f"  warning: docs site directory not found ({SITE_DIR}), skipped")

    print(f"Generated {deploy_zip}")


def build_redirects(files, version):
    lines = []

    for name, _, _ in files:
        target = f"{R2STORAGE_URL_BASE}/{version}/{name}"
        lines.append(f"/{name}    {target}    302")

    for path, target in GUI_REDIRECTS:
        lines.append(f"{path}    {target}    302")

    REDIRECTS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Generated {REDIRECTS_FILE}")


def collect_release_files():
    files = []

    for f in BIN_DIR.iterdir():
        if f.is_file() and f.name.startswith("gonc") and not f.name.endswith(".zip"):
            sha = sha256_of_file(f)
            size = human_size(f.stat().st_size)
            files.append((f.name, size, sha))

    return sorted(files, key=lambda item: item[0])


def build_download_table(files):
    if not files:
        return '<div class="empty-state">No release files found.</div>'

    rows = [
        '<table class="download-table">',
        "<thead>",
        "<tr>",
        '<th><span class="lang-zh">文件名</span><span class="lang-en">Filename</span></th>',
        '<th><span class="lang-zh">大小</span><span class="lang-en">Size</span></th>',
        "<th>SHA-256</th>",
        "</tr>",
        "</thead>",
        "<tbody>",
    ]

    for name, size, sha in files:
        safe_name = html.escape(name, quote=True)
        safe_size = html.escape(size)
        safe_sha = html.escape(sha)
        rows.append(
            "<tr>"
            f'<td><a class="file-link" href="{safe_name}" download="{safe_name}">{safe_name}</a></td>'
            f"<td>{safe_size}</td>"
            f'<td><code class="sha">{safe_sha}</code></td>'
            "</tr>"
        )

    rows.extend(["</tbody>", "</table>"])
    return "\n".join(rows)


def build_pages():
    files = collect_release_files()

    version = get_gonc_version()
    if not version.startswith("v"):
        raise Exception("Unable to determine gonc version")
    print(f"Current version {version}")

    page = (
        PAGE_TEMPLATE.replace("$VERSION", html.escape(version))
        .replace("$DOWNLOAD_TABLE", build_download_table(files))
    )

    INDEX_HTML.write_text(page, encoding="utf-8")
    print(f"Generated {INDEX_HTML}")
    NOTFOUND_HTML.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><title>404 Not Found</title></head>"
        "<body><h1>404 Not Found</h1><p>The file you requested does not exist.</p></body></html>",
        encoding="utf-8",
    )
    print(f"Generated {NOTFOUND_HTML}")
    build_headers(files)
    build_redirects(files, version)

    file_paths = [
        INDEX_HTML,
        NOTFOUND_HTML,
        REDIRECTS_FILE,
    ]
    os.makedirs(BIN_DIR / version, exist_ok=True)
    for name, _, sha in files:
        shutil.copy2((BIN_DIR / name), (BIN_DIR / version / name))
        if sha != sha256_of_file(BIN_DIR / version / name):
            raise Exception(f"Copied file checksum mismatch: {name}")
    shutil.copy2(INDEX_HTML, (BIN_DIR / version / "index.html"))

    build_zip(file_paths, f"deploy_{version}.zip")
    for f in file_paths:
        os.remove(f)


if __name__ == "__main__":
    build_pages()
