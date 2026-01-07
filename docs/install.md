# 安装指南

`gonc` 被设计为**单文件、零依赖**的轻量级工具。无论你使用 Windows、Linux 还是 macOS，通常只需要下载一个二进制文件即可开始使用。

## 📦 预编译二进制包 (推荐)

这是最简单的安装方式。请访问 [GitHub Releases](https://github.com/threatexpert/gonc/releases) 页面下载最新版本，或者从[Cloudflare CDN](https://www.gonc.cc/)下载速度更快。

=== "Linux / macOS"

    **1. 下载并安装**
    
    以 Linux amd64 为例（请根据你的架构替换 URL）：

    ```bash
    # 下载二进制文件
    curl -L https://www.gonc.cc/gonc_linux_amd64 -o gonc

    # 添加执行权限
    chmod +x gonc

    # 移动到系统路径 (可选，方便全局调用)
    sudo mv gonc /usr/local/bin/
    ```

    **2. 验证安装**
    
    ```bash
    gonc -h
    ```

=== "Windows"

    **1. 下载**
    
    下载 `gonc.exe`。

    **2. 安装**
    
    你可以直接双击运行，但为了在 CMD 或 PowerShell 中随时调用，建议：
    
    1. 在 C 盘根目录创建一个文件夹，例如 `C:\Tools`。
    2. 将下载的 `.exe` 放入该文件夹，并重命名为 `gonc.exe`。
    3. 将 `C:\Tools` 添加到系统的 **PATH 环境变量** 中。

    **3. 验证**
    
    打开一个新的 CMD 窗口，输入：
    ```cmd
    gonc -h
    ```

=== "Android (Termux)"

    如果你想在手机上运行 gonc：

    ```bash
    pkg install wget
    wget https://www.gonc.cc/gonc_android_arm64 -O gonc
    chmod +x gonc
    mv gonc $PREFIX/bin/
    ```

---

## 🐹 通过 Go 编译安装

如果你是一名 Go 开发者，或者希望体验最新的开发版功能，可以自己编译。

!!! requirement "环境要求"
    需要 Go 1.24.3 或更高版本。

```bash
# 安装最新版本
git clone https://github.com/threatexpert/gonc.git
cd gonc
sh build-local.sh  # Windows下用 build.bat
```
