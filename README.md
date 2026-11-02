# storage-analyzer

Windows 磁盘空间分析 + 交互式一键清理报告。

只读扫描，删除必须由你在网页上**预览后确认**。零第三方依赖，只需要 Python 3.8+。

---

## 能做什么

对着 agent 说一句"帮我看看 C 盘怎么满了"，它会：

1. **只读**扫描磁盘（不写、不删、不改权限）；
2. 找出占空间最大的目录，逐个溯源"这是什么东西"；
3. 按 🟢可自动清理 / 🟡需人工判断 / 🔴谨慎清理 分级；
4. 起一个本地网页：删除前先预览文件清单，执行时显示进度条，
   单项失败自动跳过，看完点"结束服务"进程退出。

---

## 环境要求

- **Windows 10 / 11**
- **Python 3.8+**（装的时候勾选 "Add Python to PATH"）
- 不需要管理员权限即可运行；扫描阶段建议提权（见下）

---

## 两种用法

### A. 在 Windows 主机上直接用

```powershell
cd <仓库目录>
python scripts\detect_tools.py --json
python scripts\scan.py --full --elevate --profiles 10 --out "%TEMP%\storage_scan.json"
python scripts\server.py %TEMP%\storage_analysis.json
```

### B. 在 WSL 里操作 Windows

WSL 里**不要**用 WSL 自己的 Python 去遍历 `/mnt/c`（9p 文件系统慢 5–10 倍，而且读不到
junction 属性）。要调用 Windows 侧的 Python：

```bash
# 找到 Windows Python
cmd.exe /c "where python"

# 用它跑扫描（路径用 Windows 写法）
/mnt/c/Users/<USER>/AppData/Local/Programs/Python/Python312/python.exe \
    scripts/scan.py --full --elevate --out "C:\\Users\\<USER>\\AppData\\Local\\Temp\\storage_scan.json"
```

注意：**服务端必须在 Windows 侧运行**，因为它要调用 `SHFileOperationW` 把文件送进回收站。
从 WSL 起服务用：

```bash
cmd.exe /c "cd /d <仓库目录> && python scripts\server.py %TEMP%\storage_analysis.json"
```

路径转换：`wslpath -w /mnt/c/foo` → `C:\foo`。

---

## 关于提权

扫描时**默认建议提权**（`--elevate`），因为普通权限读不到
`WindowsApps`、`System Volume Information`、其他用户目录，报告会出现一片"权限不足"。

`--elevate` 会弹**一次** UAC，重新以管理员身份跑完并把结果写回临时文件。
你点"是"即可；点"否"会自动退回普通权限，不会反复弹窗。

删除**不需要**管理员权限——回收站是用户级操作。

---

## 安全设计

- 扫描阶段**绝对只读**：只读元信息，不写文件、不删文件。
- 删除只发生在你点击并**确认预览**之后。
- 三重约束：
  1. **精确白名单**——只有报告里列出的具体路径能被删；
  2. **系统路径黑名单**——`C:\Windows`、`Program Files`、`System Volume Information`、
     `$Recycle.Bin` 等一律拒绝；盘符根也拒绝；
  3. **本地回环 + 随机 token**——只监听 127.0.0.1，每次启动换 token。
- "移到回收站"可还原；"直接删除"不可恢复，按钮会二次确认。

> ⚠️ 移到回收站**不会立刻释放空间**，要清空回收站才真正腾出来。

---

## 目录结构

```
storage-analyzer/
├── SKILL.md                     # agent 读的完整说明（流程、分级、坑）
├── README.md                    # 本文件
├── assets/
│   └── report_template.html     # 单文件报告模板（内嵌 CSS/JS，无外链）
├── references/
│   └── windows.md               # Windows 数据布局 + 返回码对照
└── scripts/
    ├── scan.py                  # 只读扫描器（多盘 + 内容画像 + 预算控制 + 提权）
    ├── detect_tools.py          # 探测本机装了 TreeSize / WizTree / Everything 没有
    ├── build_report.py          # 静态只读报告（无删除按钮）
    └── server.py                # 交互式服务（预览 / 进度 / 跳过 / 结束服务）
```

---

## 常见问题

**Q：报 `SHFileOperation failed (code 124 / 0x7C)`？**
目录里有文件正被程序占用。报错会直接写是哪个进程，关掉它再点一次；
也可以点"跳过失败项，继续"先把其余的处理掉。

**Q：为什么有的目录显示"权限不足"？**
`WindowsApps`、`System Volume Information` 这类受保护目录普通权限读不到。
用 `--elevate` 重扫即可。系统保留区会单独灰字列出，不算遗漏。

**Q：点了删除但磁盘空间没变大？**
文件进了回收站。清空回收站才真正释放。

**Q：关掉页面后按钮还能用吗？**
不能。按钮依赖本地服务进程，服务停了就失效。重新需要就再运行一次 `server.py`。
