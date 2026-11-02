# Windows 数据布局与分级参考

分析 Windows 扫描结果时读这份。讲"东西存在哪、怎么辨认、归哪一级"。

---

## 多盘符

Windows 通常多个盘（C:、D:…），`scan.py --all-drives` 会逐盘输出 `system.full_scans[]`。

**扫描不设限**，但**清理建议要分盘**：

- **系统盘（C:）**：缓存、AppData、临时文件、Windows 组件都在这——三灯主要给这块。
- **数据盘（D:/E:/…）**：一般是用户资料、游戏、下载。默认归 🟡，让用户自己判断，
  **不要自动给删除按钮**；除非确认是纯缓存（例如某软件的 `Cache` 子目录）。
- 每块盘单独给结论（"D 盘 805 GB 已用，最大是 xxx"），不要混成一个总数。

`--budget` 是全局预算，扫不完的盘标 `skipped`，报告里要写明"该盘未扫描/未扫完"。

## 关键目录

| 目录（环境变量） | 装什么 | 典型分级 |
|---|---|---|
| `%LOCALAPPDATA%`（`C:\Users\<u>\AppData\Local`） | 浏览器缓存、应用数据、Temp，最大头 | 缓存 🟢 / 应用数据 🟡 |
| `%LOCALAPPDATA%\Temp`、`%TEMP%` | 临时文件 | 🟢 |
| `%APPDATA%`（Roaming） | 应用配置/数据 | 🟡 |
| `%LOCALAPPDATA%\<Vendor>\<App>\User Data` | Electron 应用的完整浏览器配置（书签/登录态/IndexedDB） | 🟡 |
| 浏览器缓存 `%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache`、Edge 同构 | 浏览器缓存 | 🟢 |
| `...\User Data\OptGuideOnDeviceModel`、`EdgeLLMOnDeviceModel` | **端侧 AI 模型权重**（weights.bin / model.onnx.data，动辄 2–4 GB） | 🟢 |
| `%USERPROFILE%\.cache`、`.npm`、`.gradle`、`.m2`、`.nuget\packages`、`%LOCALAPPDATA%\pip\Cache` | 开发缓存 | 🟢 |
| `%LOCALAPPDATA%\D3DSCache`、`NVIDIA\DXCache` | 显卡着色器缓存 | 🟢 |
| `%LOCALAPPDATA%\ms-playwright` | Playwright 整套浏览器副本 | 🟡 |
| `C:\Program Files`、`Program Files (x86)` | 应用本体 | 🔴 仅重复/想卸时上灯，否则归蓝色 |
| `C:\ProgramData` | 全机共享的应用数据（NVIDIA 驱动包、杀软病毒库、VS 安装器缓存） | 视内容 🟢/🔴 |
| `%USERPROFILE%\Downloads` 的 exe/msi | 安装包残留 | 🟢 |
| `C:\$Recycle.Bin` | 回收站 | 🟡 提示用户清空 |
| `C:\tmp`、`C:\TEMP` 这类**根目录临时目录** | 自动化脚本/工具的草稿区，常见大量带时间戳的 `--user-data-dir` | 🟢（但必须逐条列，不能整目录删） |

---

## 系统占用（不上灯，归蓝色"系统及其他"）

- `C:\Windows\WinSxS`：组件存储，**绝不能手删**，且数字被**硬链接放大**（显示 28 GB，实际独占小得多）。
  只能 `DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase`。
- `C:\Windows\SoftwareDistribution\Download`：Windows Update 缓存，用磁盘清理处理。
- `C:\Windows\System32\DriverStore\FileRepository`：驱动库，旧版本可用
  `pnputil /enum-drivers` + `pnputil /delete-driver oemXX.inf /uninstall` 清。
- `C:\Windows\Installer`：MSI/MSP 补丁缓存，**卸载/修复时要回读，删了软件没法卸** → 🔴。
- `hiberfil.sys`（休眠，≈内存大小）、`pagefile.sys`（虚拟内存）、`swapfile.sys`：
  系统管理，**不是删除对象而是开关**。hiberfil 用 `powercfg /h off` 或 `/type reduced`；
  pagefile 在"系统属性 > 高级 > 性能 > 虚拟内存"里迁到别的盘。
- 间接释放：设置 > 系统 > 存储 > 存储感知；`cleanmgr`（磁盘清理）；
  扩展磁盘清理勾选"Windows 更新清理"。

---

## 辨认方法（Windows 特有）

1. **Chromium 家族**：目录里有 `Local State`、`Default\`、`Cache`、`GPUCache`、`GrShaderCache`。
   出现在 `C:\tmp\trc-xxx-<毫秒时间戳>` 这种位置 = 某工具用 `--user-data-dir` 起的一次性配置。
2. **Electron 应用**：`%LOCALAPPDATA%\<AppName>` 下同时有 `Cache`、`Code Cache`、`blob_storage`。
3. **虚拟机镜像**：`.vhdx` / `.vhd` / `.vmrs`，体积 GB 级，**不能整目录删**（会丢会话）。
4. **端侧 AI 模型**：`weights.bin`、`model.onnx.data`、`*.gguf`，删了浏览器/应用会自动重下。
5. **更新器残留**：`@xxx-updater` 目录里孤零零一个 `installer.exe`。
6. **补丁备份**：`xxx.asar` 与 `xxx.asar.<tool>-orig` 成对出现 = 某个工具打过补丁留的原件。

---

## 删除机制

`server.py` 在 Windows 用 ctypes 调 `SHFileOperationW`(`FOF_ALLOWUNDO` | `FOF_NOCONFIRMATION`
| `FOF_SILENT` | `FOF_NOERRORUI`) 送进回收站；纯标准库，不需要 pywin32。

### 返回码对照（重要）

| code | 常量 | 真实含义 |
|---|---|---|
| 0 | — | 成功 |
| 120 | `DE_ACCESSDENIEDSRC` | 拒绝访问，需要管理员 |
| 121 | `DE_PATHTOODEEP` | 层级过深 |
| **124** | `DE_INVALIDFILES` | **路径无效 —— 实测 99% 是目录内有文件被进程占用** |
| 128 | `DE_FILENAMETOOLONG` | 超过 260 字符 |
| 131 | `DE_FILE_TOO_LARGE` | 超出回收站配额 |
| 132 | `DE_RECYCLE_INCOMPLETE` | 未能完整放入回收站 |

**124 的排查顺序**：先找占用进程（`Win32_Process.ExecutablePath` 前缀匹配目标目录），
让用户关掉再试；确认没有进程后，再怀疑超长路径。

### 白名单与允许根

- **精确白名单**：只有报告里 `trash_paths` 列出的绝对路径才允许删，这是唯一的核心护栏。
- **允许根**：从报告自身推导（`盘符 + 第一层目录`），再并入 `$HOME`、`%TEMP%` 和可选 `allow_roots`。
  不要把根写死成 `$HOME`——`C:\tmp`、`C:\ProgramData\...` 这类合法缓存会全被拒。
- **拒绝清单**：`C:\Windows`、`Program Files`、`ProgramData\Microsoft`、`$Recycle.Bin`、
  `System Volume Information`、`Recovery`、`Boot`、`PerfLogs`。
- **深度护栏**：拒绝盘符根（`C:\`）和顶层目录（`C:\Users`）。

### 回收站不释放空间

`移到回收站` 只是把文件挪进 `C:\$Recycle.Bin\<SID>\$R…`，**同一卷内移动，空间一点没少**。
必须清空回收站才真正释放。报告里要写清楚这句话，否则用户会以为按钮坏了。

---

## 提权

绝大多数扫描**不需要管理员**：普通用户跑 `os.scandir` 能覆盖 99% 以上已用空间，
被 ACL 拒绝的几乎全是系统区（`WindowsApps`、`System Volume Information`、`$Recycle.Bin`、杀软金库），
本来也不该清。

需要提权只有三种：WizTree 走 MFT、核实 `WindowsApps`、清 `ProgramData` 下管理员级缓存。

**提权方式优先级**：让用户开一个管理员终端跑 > `Start-Process -Verb RunAs -Wait` >
`sudo.exe`（Win11 24H2+，默认强制新窗口，stdout 拿不回来）。

铁律：**提权进程的输出一律写文件再读**，不要指望捕获 stdout；UAC 必须用户点"是"，
发起后几秒内没出现输出文件就明确让用户去点。
