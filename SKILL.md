---
name: storage-analyzer
description: >
  Windows 磁盘空间分析（只读扫描 + 交互式一键清理报告）。
  自动识别系统盘与全部本地固定盘，找出占空间大户，按 🟢可自动清理 / 🟡需人工判断 /
  🔴谨慎清理 分级，生成可折叠、命令可一键复制的本地网页，支持删除前预览、进度条、
  失败跳过、一键结束服务。扫描全程只读。
  在以下场景使用：用户说"存储分析""磁盘满了""C盘/硬盘满了""空间不够""清理空间"
  "清理磁盘""占空间""哪些东西占地方""帮我看看存储""看一下电脑存储/空间"
  "存储空间""电脑空间不够""内存满了/不够/不足"（中文口语里"内存"常指存储空间）
  "storage analysis""disk cleanup""清缓存""磁盘清理"；或用户抱怨电脑没空间、
  想知道什么东西吃硬盘、想要清理建议时。
  注意：若用户明确指运行内存/RAM（"哪个进程吃内存""内存占用高"想看任务管理器），
  那是 RAM 不是存储，不属于本 skill。
---

# Storage Analyzer (Windows)

对 Windows 做一次**只读**存储分析，产出一个**可交互的一键清理网页**。

流程：识别路径形态 → 探测工具 → 扫描 → 覆盖率校验 → 内容画像 → 溯源 →
分级 → 起服务 → 对话摘要。

---

## 0. 铁律

- **扫描阶段全程只读。** 只允许读元信息：`os.scandir` / `stat` / `df` / 注册表查询。
  禁止 `del`、`rmdir`、`Remove-Item`、`mv`、清空回收站、改权限、改注册表等写操作。
- **删除只由用户在网页上点击触发**，并且必须经过"预览 → 确认"两步。
- **用户说"别删"就一个字节都别动**，包括你自己的测试——测试一律用自建 fixture。
- **估算要标注**：所有"可释放空间"都是估算值。
- **路径与命令保留原文**，Windows 反斜杠不要转成正斜杠。

---

## 1. 两种运行环境（都要支持）

| 场景 | 判断 | 路径写法 | Python |
|---|---|---|---|
| **Windows 主机** | `sys.platform == "win32"`，直接跑 | `C:\\`、`D:\\`… | `python` / `py -3` |
| **WSL2 里操作 Windows** | `uname` 含 `microsoft-standard-WSL2`，`/mnt/c` 存在 | `/mnt/c` = `C:`，`/mnt/d` = `D:` | 用 **Windows 侧** `python.exe`，不要用 WSL 的 python 遍历 `/mnt/c` |

**WSL 的两个坑：**

1. **不要用 WSL 的 Python 递归 `/mnt/c`**——9p 文件系统比原生慢 5–10 倍，
   而且拿不到 `st_file_attributes`（判断不了 junction）。
   ```bash
   # 对：调用 Windows 侧解释器
   /mnt/c/Users/<USER>/AppData/Local/Programs/Python/Python312/python.exe scripts/scan.py --full
   # 或直接
   cmd.exe /c "python <SKILL_ROOT>\\scripts\\scan.py --full"
   ```
2. **WSL 里的路径要翻译**：`/mnt/c/foo` ↔ `C:\\foo`。写进分析 JSON 的
   `trash_paths` **必须用 Windows 原生路径**，因为服务端跑的是 Windows Python。
   转换：`wslpath -w /mnt/c/foo` → `C:\\foo`。

> 服务端（`server.py`）必须在 **Windows 侧**运行——它调用 `SHFileOperationW` 移回收站。

---

## 2. 快速开始

```bash
# 0) 探测本机装了哪些扫描工具（PATH / 安装目录 / 注册表 / 开始菜单）
python scripts/detect_tools.py --json

# 1) 扫描。建议第一次就带 --elevate，让用户点一次 UAC，后面不再为权限发愁
python scripts/scan.py --full --elevate --profiles 10 --out "%TEMP%\storage_scan.json"

#    只扫系统盘（默认） / 指定盘 / 全部盘
python scripts/scan.py --full
python scripts/scan.py --full --drive D: --drive E:
python scripts/scan.py --full --all-drives --budget 1800

# 2) 覆盖率校验：扫描总量 vs 卷已用，按 3.5 的三种情况判读
# 3) 对每个大目录溯源：本地取证 → 必要时联网 → 交叉验证 → 不确定就写"不知道"
# 4) 写 analysis.json（schema 见 scripts/build_report.py 顶部注释）

# 5) 起交互式报告
python scripts/server.py %TEMP%\storage_analysis.json
```

交付：报告地址 + 可释放估算 + 最该清的 2–3 项 + 风险最高的一项 + "看完点右下角结束服务"。

---

## 3. 扫描

### 3.1 会不会"扫不完"

**全量遍历是有限的**——文件数就那么多。一台普通开发机的系统盘通常是
**几十万到上百万个文件、1–3 分钟**能走完。真正的风险只有三种：

| 风险 | 现象 | 对策 |
|---|---|---|
| 重解析点成环 | `C:\\Users\\All Users`、`C:\\Documents and Settings` 指回自己 | 跳过 `st_file_attributes & 0x400`，不跟随、不计数 |
| 路径超过 260 字符 | `OSError` 或计数错乱 | 打开时加 `\\\\?\\` 前缀 |
| 慢盘（WSL 的 `/mnt/c`） | 同样的盘慢 5–10 倍 | 用 Windows 侧 Python |

**两道硬预算**（`scan.py` 内置）：

- `--budget 900`：总时间上限（秒）
- `--max-entries`：条目上限（默认 3,000,000，改代码里的 `max_entries`）

任意一个到顶就停，输出 `truncated: true`。报告必须写明"未扫完，结论仅供参考"。
**宁可出一份标注截断的报告，也不要卡住。**

### 3.2 输出裁剪：扫全量，只留有用的

遍历全量，但输出要裁剪，否则 JSON 上百 MB 没法读：

- **目录**：保留 `depth <= 6` **或** `size >= 1 GB`
- **文件**：只单列 `>= 100 MB` 的
- 其余全部聚合进父目录字节数

### 3.3 内容画像：这个目录里到底是什么

一个 12 GB 的目录叫"缓存"，里面可能是虚拟机镜像、模型权重，也可能是你的设计稿。
**只看目录名就下结论一定会翻车。**

`scan.py --full --profiles N` 会挑两类目录做画像：**体积最大的 N 个** +
**自身文件占比最高的 N 个**（共约 2N 个）：

| 字段 | 含义 | 怎么用 |
|---|---|---|
| `own_bytes` / `subdir_bytes` | 体积是自己的文件撑的，还是子目录撑的 | own 高 → 看文件类型；sub 高 → 顺着 `top_subdirs` 往下钻 |
| `ext` | 直接子文件扩展名直方图（类型 / 字节 / 个数） | `vhdx` `bin` `gguf` `mp4` 一眼看出是什么 |
| `top_files` | 最大的 3 个直接文件 | 一个 `rootfs.vhdx 8.26 GB` 胜过千言万语 |
| `top_subdirs` | 最大的 5 个直接子目录 | 继续下钻的入口 |
| `stray_bytes` / `stray_ratio` | 混进来的文档/媒体/压缩包占比 | > 0.3 就要警惕：这不像纯缓存，按 🟡 处理 |

**关键设计：画像只读一层，不递归。** 成本 O(直接子项数)，与目录多深无关。

### 3.4 工具探测与优先级

**第 0 步：先探测，不猜。**

```bash
python scripts/detect_tools.py --json
```

四层查找：**PATH → 常见安装目录 glob → 注册表 Uninstall 项 → 开始菜单快捷方式（仅线索）**。
输出直接给 `recommended` 和可套用的 `cmd_template`：

```json
{
  "recommended": "TreeSize",
  "tools": [{
    "name": "TreeSize", "found": true,
    "exe": "<DRIVE>:\\Tools\\TreeSize\\TreeSize.exe", "source": "common-path",
    "needs_admin": false, "kind": "disk-analyzer",
    "cmd_template": "\"<DRIVE>:\\Tools\\TreeSize\\TreeSize.exe\" /SCAN \"{drive}\" /CSV \"{out}\" /EXPAND 6"
  }]
}
```

**不要硬编码路径**——每台机器装的位置都不一样。

**第 1 步：按优先级选**

| 优先级 | 条件 | 用什么 | 耗时/盘 | 说明 |
|---|---|---|---|---|
| **P1** | 探测到 TreeSize | TreeSize | 快 | 免提权、可深度导出 |
| **P2** | 只有 WizTree 且能提权 | WizTree | 最快 | 读 MFT；提不了权就降级 |
| **P3** | 都没有 / 不是 NTFS | `scan.py --full` | 中 | 零依赖，唯一带内容画像 |

**第 2 步：无论如何跑一次 `scan.py --full`**

外部工具只回答"谁大"，**不给内容画像、不给预算控制**。`profiles` 是判断
"缓存还是你的设计稿"的唯一依据，同时充当**交叉验证**。

**第 3 步：工具坑**

- **TreeSize**：默认 `/EXPAND 1` **只导出顶层**，必须显式给 `/EXPAND 6` 左右。
- **WizTree**：⚠️ 非管理员运行会**静默产出 0 字节文件**，不报错——拿到空文件先怀疑权限。
- **Everything**：不是磁盘分析器，只索引文件名、不做目录大小汇总；
  适合"找出所有 >500 MB 的文件"，不适合"看谁占了盘"。

### 3.5 覆盖率校验（必须做）

```
扫描累计字节数  vs  卷已用字节数
```

| 结果 | 含义 | 处理 |
|---|---|---|
| 扫描 **<** 已用（差 > 1%） | 确实有没读到的地方 | 列出被拒目录，说明"未计入" |
| 扫描 **≈** 已用（±2%） | 正常 | 报告写一句覆盖率 |
| 扫描 **>** 已用（超 5% 以上） | 不是错误，是口径差：硬链接重复计数、稀疏文件按逻辑大小、压缩文件按未压缩 | 写明口径，别当 bug 修 |

**硬链接说明**：`WinSxS` 里大量文件是硬链接，从多个路径都能看见，按路径累加会重复计数。
报告里给这类目录的体积时**必须注明"被硬链接放大"**，不能说"删了能省 28 GB"。

### 3.6 权限：默认提权，一次到位

**结论：默认用管理员权限扫描。** 理由：

- 普通权限下 `WindowsApps`、`System Volume Information`、杀软金库、其他用户目录
  都读不到，报告会出现一片"权限不足"，用户还得再问一次"那这些到底多大"。
- 提权只影响**扫描**，删除仍然走网页（回收站是用户级操作，不需要管理员）。

**做法：第一次扫描就带 `--elevate`。**

```bash
python scripts/scan.py --full --elevate --profiles 10 --out "%TEMP%\storage_scan.json"
```

`--elevate` 会：

1. 检测当前是否已是管理员（`IsUserAnAdmin`）；
2. 不是的话，用 `Start-Process -Verb RunAs -Wait` 重新拉起自己；
3. 子进程把 JSON 写到临时文件，父进程读回来打印——**绝不依赖捕获提权进程的 stdout**；
4. 用户只需在 UAC 弹窗点**一次**"是"。

**用户拒绝 UAC 时**：自动退回普通权限扫描，报告里的 `denied_summary` 会给出
`acl_paths`，并提示"以管理员身份重跑可读取"。不要反复弹 UAC。

**读不到的目录分三类写进报告：**

| 类型 | 典型路径 | 处理 |
|---|---|---|
| 系统保留区 | 每块盘都有的 `System Volume Information`、`$RECYCLE.BIN`、`Recovery`、`PerfLogs`、`Config.Msi` | 灰字列出，**不算遗漏** |
| ACL 受限 | `WindowsApps`、杀软数据目录、其他用户目录 | 黄字，提示可提权读 |
| 其他/被独占 | —— | 单独说明 |

⚠️ **每块盘都有一个 `System Volume Information`**，不要每块盘都报一次"可能遗漏体量"。

---

## 4. 遇到不认识的路径

按顺序，**不要跳步**：

1. **本地取证**：看结构（是不是 Chromium 的 `Local State / Default / Cache`）、
   看最后写入时间、看目录里的 `*.json` / `*.log`、看占用它的进程、看安装记录。
2. **联网检索**：目录名 + `what is` / `safe to delete`、报错码 + API 名。
3. **交叉验证**：检索说法必须能在本机验证（真装了那个软件、目录结构对得上、文件类型对得上）。
   **冲突时以本地运行证据为准。**
4. **说不准就写"不知道"**：
   > **不确定**：目录结构是 `<事实>`，但没找到能确认它属于哪个程序的证据；
   > 建议先 `<最小成本确认动作>`，确认前按 🟡 处理。

禁止用"可能是/一般来说/应该是"包装成结论。

---

## 5. 分级

- 🟢 **可自动清理**：纯缓存、临时文件、安装包残留、明确可再生。
- 🟡 **需人工判断**：含用户数据或有判断成本（离线视频、文档、虚拟机镜像、聊天记录）。
- 🔴 **谨慎清理**：想动但建议别手删（重复安装的应用、运行中应用的核心数据）。
  只给"在资源管理器打开（去卸载）"，不给删除按钮。

**三灯只放"有清理决策"的项**；系统文件、海量零碎小文件归蓝色"系统及其他"。

`size` 写"约 14 GB"即可，不要写"（估算）"。
`tier_stats` 三个值必须以可解析的 GB 数字开头。

---

## 6. 生成报告

### 6.1 启动

```bash
python scripts/server.py %TEMP%\storage_analysis.json
```

起在 `127.0.0.1` + 随机端口 + 每次随机 token，自动开浏览器。

### 6.2 页面结构

1. **磁盘总览**：容量 + 分段进度条（绿/橙/红/蓝）+ 三色 pill
2. **占用排行 Top5**
3. **执行建议**——**默认折叠**，点击展开（见 6.3）
4. **🟢🟡🔴 折叠卡片**：名称 + 体积 + 展开箭头
5. **未读取区域**：系统保留区（灰） / 权限不足（黄，可折叠）
6. **长期优化建议**：分组卡片，带命令复制
7. 右下角常驻 **■ 结束服务**

### 6.3 执行建议必须默认折叠

它排在最前面、条目又多，展开会把下面的清理卡片顶到屏幕外。用 `<details>`：

```html
<details class="sec fold">
  <summary><h2>执行建议 <span class="count">5 条</span></h2><span class="fold-hint">点击展开</span></summary>
  <div class="summary">…</div>
</details>
```

默认 `open` 属性**不要加**。展开后是编号卡片：

```json
{"title": "先清临时目录的自动化残留", "size": "约 22.7 GB", "tier": "green",
 "detail": "Chromium 的 --user-data-dir 目录，最后写入停在十天前。",
 "cmd": "Get-ChildItem <DIR> -Directory -Filter trc-* | Remove-Item -Recurse -Force"}
```

按"收益 × 安全性"排序，5–7 条最合适。

### 6.4 删除前必须预览

点"移到回收站/直接删除"时，**先弹预览，再执行**。预览接口：

```
POST /preview  {token, paths[]}
→ {"ok": true,
   "total": {"files": 47, "dirs": 6, "bytes": 8900000},
   "items": [{"path": "...", "kind": "dir", "files": 12, "dirs": 2, "bytes": 2400000,
              "partial": false,
              "samples": [{"rel": "sub1/file_000.bin", "size": 200000}]}]}
```

**文件名怎么展示**（这是体验关键）：

- **按目标路径分组**，每组一行标题：`[文件夹] …\pvtest\cache_a` + 右对齐总体积
- 路径只显示**最后 3 段**，前面用 `…\` 省略，避免长路径撑破弹窗
- 组内显示 `12 个文件 · 2 个文件夹`
- 展开后列**最大的 N 个文件**：只显示**相对路径**（`sub1/file_000.bin`）+ 右对齐体积
- 超长文件名**中间省略**（`very-long-nam…e.bin`），保留头尾便于辨认
- 顶部一行汇总：`共 47 个文件 · 6 个文件夹 · 合计 8.5 MB`
- 大目录超时 → 标 `partial: true`，显示"目录较大，仅统计了前面一部分"，**不要让弹窗转圈**

### 6.5 进度条

大批量操作（几百个路径）必须给进度，否则用户以为卡死。

```
POST /action  → {"ok": true, "job_id": "xxx", "total": 214}     # 立刻返回
GET  /progress?id=xxx&token=... →
   {"done_count": 11, "failed_count": 1, "total": 214, "current": "C:\\...\\trash", "finished": false}
```

- 每 300 ms 轮询
- 进度 = `done_count + failed_count`（**失败也算走完**，否则永远差一截）
- 文案：`12 / 214（6%）· 当前：trash`，只取路径最后一段
- 完成后 600 ms 淡出

### 6.6 失败跳过

一条路径失败（被占用、拒绝访问、超长）**不能拖累整批**：

- 服务端逐条处理，失败记进 `failed[]` 后继续
- 响应 `{ok, partial, done[], failed[], done_count, failed_count}`
- 前端：全成功 → 打勾；部分成功 → `⚠ 已处理 12 项，1 项失败` + **「跳过失败项，继续」**
- `code 124 / DE_INVALIDFILES` 基本都是**文件被进程占用**，错误文案要直接写出进程名

### 6.7 结束服务

右下角固定 `■ 结束服务` → `POST /shutdown` → `srv.shutdown()` → 页面提示"服务已结束"，
按钮全部置灰。没有这个按钮，用户只能去任务管理器杀 `python.exe`。

### 6.8 网页实现骨架

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| GET | `/` | — | 注入数据后的 HTML |
| POST | `/preview` | `{token, paths[]}` | 文件数/目录数/字节数 + 最大文件样本 |
| POST | `/action` | `{token, paths[], mode, stop_on_error?}` | 立刻返回 `{ok, job_id, total}` |
| GET | `/progress?id=&token=` | — | 进度状态 |
| POST | `/shutdown` | `{token}` | 停止服务 |

模板两个占位符：`__REPORT_DATA__`（analysis JSON）、`__DELETE_CONFIG__`
（`null` = 静态只读；`{token, endpoint, progress, preview, shutdown}` = 服务模式）。

**安全四件套：**

1. **精确白名单** — 每个路径必须 realpath 后命中报告里的 `trash_paths`
2. **token** — 每次启动随机，随 HTML 下发
3. **Host 校验** — 只接受 `127.0.0.1` / `localhost`
4. **只绑 127.0.0.1**，随机端口

**路径护栏：** 拒绝盘符根（`C:`）；按目录名拒绝系统保留目录（任何盘符）；
按前缀拒绝 `C:\Windows`、`Program Files`；按精确拒绝 `C:\Users`、`C:\ProgramData`。
**第一层目录（`D:\Downloads`）必须放行**，否则数据盘的清理目标全被误杀。

### 6.9 临时文件

服务本身不写盘（`sys.dont_write_bytecode = True`，无 `__pycache__`）。会留下的是：

| 产物 | 位置 |
|---|---|
| 扫描 JSON / 分析 JSON | `%TEMP%\storage_scan.json` 等 |
| 提权重扫的临时输出 | `%TEMP%\storage_scan_admin_*.json` |
| **回收站里的文件** | `C:\\$Recycle.Bin` |

必须告诉用户：**"移到回收站"不会立刻释放空间，要清空回收站才真正腾出来。**

---

## 7. 长期优化建议怎么写

`summary.long_term` 支持字符串或对象数组。**对象形式更清楚**：

```json
{"title": "组件存储清理", "detail": "WinSxS 里大量是硬链接，体积被放大，只能清旧组件。",
 "cmd": "DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase"}
```

建议覆盖这些方向：

1. **组件存储**：`DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase`
2. **驱动库**：`pnputil /enum-drivers` 找旧版本 → `pnputil /delete-driver oemXX.inf /uninstall`
3. **系统临时文件**：`cleanmgr /sageset:1` 勾选"Windows 更新清理""传递优化文件""临时文件"→ `cleanmgr /sagerun:1`
4. **存储感知**：设置 → 系统 → 存储 → 存储感知，自动清临时文件与回收站
5. **虚拟内存迁移**：系统属性 → 高级 → 性能 → 虚拟内存，从系统盘迁到数据盘
6. **休眠**：`powercfg /h off` 或 `/type reduced`
7. **定期复查**：用 TreeSize / WizTree 做对比扫描，留 CSV 归档看增量
8. **归档**：大文件移外置盘 / NAS；下载目录设定期清理

每条都要"能照做"，不要写"建议定期清理"这种空话。

---

## 8. 已知坑

### 8.1 `SHFileOperation failed (code 124 / 0x7C)`
=`DE_INVALIDFILES`，**实际最常见是目录里有文件被进程占用**。
错误信息要调 `Win32_Process.ExecutablePath` 前缀匹配找出占用进程，直接写进文案。

| code | 常量 | 含义 |
|---|---|---|
| 120 | DE_ACCESSDENIEDSRC | 拒绝访问 |
| 121 | DE_PATHTOODEEP | 层级过深 |
| 124 | DE_INVALIDFILES | 路径无效 **/ 文件被占用** |
| 128 | DE_FILENAMETOOLONG | 超过 260 字符 |
| 131 | DE_FILE_TOO_LARGE | 超出回收站配额 |

### 8.2 路径越界
允许根**从报告自身推导**（每条 `trash_paths` 的"盘符 + 第一层目录"）+
`$HOME` + `%TEMP%`，不要写死成 `$HOME`，否则 `C:\tmp`、`C:\ProgramData\...` 全被拒。

### 8.3 顶层目录被误杀
用"路径段数 < 2"判断"太浅"会把 `D:\Downloads` 也拒了。**只拒绝盘符根**。

### 8.4 PowerShell 命令粘进 PS 报空管道
`powershell -NoProfile -Command "$d=..."` 粘进已打开的 PowerShell，外层会先展开
`$d`、`$_`。**报告里一律写裸命令**，不要套 `powershell -Command` 外壳。

### 8.5 递归不要跟着 junction 跑
`C:\Users\All Users`、`C:\Documents and Settings` 指回自己。判断
`st_file_attributes & 0x400`，跳过。

### 8.6 `hiberfil.sys` / `pagefile.sys` 是开关不是文件
不要给"删除"按钮。用 `powercfg /h off`、虚拟内存设置。

### 8.7 服务重复启动
每次随机端口，重复启动会有多个 `python.exe` 残留。启动后把端口告诉用户，
结束时用页面按钮。

---

### 8.10 调用层的三个坑（脚本本身没问题，别踩）

1. **不要用 `python -c` 内联含反斜杠的脚本/路径。** PowerShell 的 here-string
   （`@"..."@`）经多层传参会吞掉引号和反斜杠，Python 收到的是非法转义。
   改用：写成临时 `.py` 文件执行，或者直接把参数传给脚本（脚本自带参数）。
2. **不要依赖 `%TEMP%` 之类的环境变量展开。** 不同进程环境不一样，
   `os.path.expandvars` 可能拿不到。用 `--out` 显式传绝对路径，
   或 `tempfile.gettempdir()`。
3. **不要用 shell 重定向（`>`）生成 JSON。** PowerShell 5.1 的 `>` 走 `Out-File`，
   会写成 UTF-16LE 或带 BOM 的 UTF-8，下游 `json.load` 直接报
   `Unexpected UTF-8 BOM`。**用 `scan.py --out <文件>`**，Python 自己写，保证 UTF-8 无 BOM。
   （即使拿到带 BOM 的 JSON，`server.py` / `build_report.py` 也已用 `utf-8-sig` 读取，不会崩。）

> 这三条都是「调用方式」问题，不是 skill 脚本问题。遇到时先检查调用层，别去改脚本。

## 9. 对话摘要

报告起来后给一段结论先行的摘要：

1. 总可释放估算（明确是估算）
2. 最该先清的 2–3 项（绝对路径 + 体积）
3. 风险最高的一项（为什么不能手删）
4. 覆盖率一句话
5. 服务地址 + "看完点右下角结束服务"

细节让用户看网页。

---

## 10. 打包与分享

```
storage-analyzer/
├── SKILL.md
├── README.md
├── assets/report_template.html
├── references/windows.md
└── scripts/{scan.py, detect_tools.py, build_report.py, server.py}
```

整个目录一起分发——只发 SKILL.md 没有扫描器和网页模板，跑不起来。
运行前提：**Windows + Python 3.8+**，零第三方依赖。
