# 安全与发布指南（SECURITY）

本文覆盖 **API 凭证、模型请求/响应、数据许可、GitHub 发布** 四类风险。它面向准备把本仓库推送为 GitHub 私有仓库的维护者；不替代组织级安全政策。

> 一句话：**仓库里不应出现任何 API key、token、cookie、SSH key、云凭证或个人账号信息。** 所有 key 只从环境变量或本地 Kimi Code TOML 读入进程内存。

---

## 1. 威胁模型

| 资产 | 风险 | 处置 |
| --- | --- | --- |
| Provider API key（OpenCode Go / Xiaomi / DeepSeek） | 提交到 Git、写入日志、出现在截图/issue、被同机进程读取 | 环境变量或本地 TOML；不落盘；发布前扫描 |
| 模型请求/响应 | 可能回显 key、包含内部提示、包含上游代码 | 响应体脱敏；不提交 `Authorization`；只提交真实产物 |
| 上游数据（SecVulEval、Juliet） | 许可/再分发限制 | 保留来源与哈希；Juliet raw 不随仓库分发 |
| 盲评 key | 公开后可反推评分者/策略映射 | `repair_eval/packages/*/private/` 不提交 |
| 大型二进制/日志 | 超过 GitHub 100 MB 限制、仓库膨胀 | `.gitignore` + 发布前体积检查 |
| 提示注入 | 代码中的注释/字符串可能诱导模型 | 模型只做文本判断，不执行代码；system prompt 明确代码是不可信数据 |

本仓库是**课程研究产物**，不是生产系统；但一旦推送到 GitHub，即使私有仓库也应假设可能被协作者、CI、备份或未来的公开化暴露。

---

## 2. 凭证如何流动

### 2.1 共享 wrapper 与各模块读取器

`runner/run_with_kimi_config.py` 是 Tier A runner 的共享读取器：

1. 读取 `providers.<name>.api_key`；
2. 只放入子进程环境变量（默认 `OPENCODE_API_KEY`）；
3. 设置 `SECVUL_BASE_URL`；
4. 不打印 key，不写文件，不把 key 放进 `sys.argv`。

`juliet_llm/launch.py` 与 `evidence_prompt/run_with_kimi_config.py` 复用同一路径。`hybrid/run_hybrid.py`、`juliet_repair/scripts/run_repair.py`、`pair_joint/runner.py` 各自用 Python `tomllib` 读取同一 TOML（代码路径不同，但都只把 key 放入进程内存/环境变量，不落盘；产物记录 `api_key_value_stored: false`）。它们不读取 `auth.json`、`opencode.json`、keychain 或其他本地凭证。

### 2.2 运行产物

| 字段/文件 | 是否含 key | 说明 |
| --- | --- | --- |
| `manifest.json` → `api.api_key_present` | 否 | 只记录布尔值 |
| `manifest.json` → `api_key_value_stored` | 否 | 固定 `false` |
| `manifest.json` → `authorization_header_stored` | 否 | 固定 `false` |
| `manifest.json` → `api.session` | 否 | `x-opencode-session` 是随机非敏感 ID；记录 value 与 sha256 |
| `requests.jsonl` | 否 | 记录 body、prompt 元数据、User-Agent、session；不含 `Authorization` |
| `results.jsonl` | 否 | runner / `juliet_llm` 的响应体经 `sk-...` / `Bearer ...` 模式脱敏；所有模块的 manifest 不记录 `Authorization` |
| `run.log` | 否 | 只有 URL/状态码/时间；不含 key |
| `config.json` | 否 | 模型、端点、价格、参数；不含 key |

### 2.3 环境变量

推荐：

```bash
export OPENCODE_API_KEY        # 值由当前 shell/secret manager 注入
export SECVUL_MODEL="deepseek-v4.1-flash"
```

不要：

```bash
python3 runner/run_experiment.py --api-key 'sk-...'   # 会进入 shell history / 进程列表
echo 'sk-...' > creds/opencode.json                    # 会进入文件/备份
```

`--api-key-env NAME` 只指定变量名，不接收 key 值。`run_with_kimi_config.py` 的 `--kimi-config` 指向本地 TOML；该文件不应在仓库内。

---

## 3. 不提交的内容

`.gitignore` 的发布策略：

| 模式 | 原因 |
| --- | --- |
| `juliet/cache/`、`juliet/raw/`、`juliet/build/` | 146 MB 归档、58 MB 上游源码、27 MB 可执行文件；可由 `fetch_juliet.py` 恢复 |
| `traditional/dynamic/runs/*/cases/`、`*/support/` | 326 MB 逐 case 二进制/日志；`results.jsonl` 已保留 |
| `**/runs/*/cache/` | 请求缓存，和 `requests.jsonl`/`results.jsonl` 重复 |
| `juliet_repair/build/baselines/`、`sanitized/`、`support/`、`selftest/` | 编译产物；`baselines_summary.json` 与 `results.jsonl` 保留 |
| `.env`、`creds/`、`credentials/`、`secrets/`、`*.pem`、`*.key`、`*.p12`、`*.pfx`、`auth.json`、`opencode.json`、`*_api_key.json`、`*.token` | 凭证/认证材料 |
| `repair_eval/packages/*/private/` | 盲评 key（salt + 映射） |
| `__pycache__/`、`*.py[cod]`、`.pytest_cache/`、`.mypy_cache/`、`.ruff_cache/` | 本地工具缓存 |

**保留**的关键结果（不要误删）：

- `juliet/subset_units.jsonl`、`juliet/manifest.json`、`juliet/SHA256SUMS`、`juliet/FREEZE.json`、`juliet/provenance.json`；
- `traditional/static` / `traditional/dynamic` 的 `results.jsonl`、`predictions.jsonl`、`metrics.json/md`、`manifest.json`、`cases.jsonl`；
- `runner/runs/*/results.jsonl`、`requests.jsonl`、`metrics.json`、`manifest.json`；
- `benchmark/results/**/*.json`、`*.md`、`*.jsonl`；
- `report/report_extended_zh.pdf`、`report_extended_zh.tex`（27 页），`report/report_zh.pdf`、`report_zh.tex`（17 页），`results_summary.md`；
- `juliet_llm/build/`（prompt 输入与审计，不是编译产物）。

---

## 4. 发布前检查清单

以下命令在 WSL 项目根目录执行。**先确认当前分支/待提交文件，再 push。** 完整的建库/推送/验证步骤见 [`GITHUB_RELEASE.md`](GITHUB_RELEASE.md)；本文只覆盖安全门禁。

### 4.1 检查被忽略/未跟踪文件

```bash
git status --short
git status --ignored --short | head -50
```

确认 `juliet/raw/`、`juliet/cache/`、`juliet/build/`、`traditional/dynamic/runs/*/cases/`、`**/runs/*/cache/`、`__pycache__/` 只出现在 `!!`（ignored）一侧。

### 4.2 检查单文件体积（GitHub 上限 100 MB）

```bash
# 排除已知的本地缓存/原始数据；干净 clone 中这些路径本来就不存在。
find . -path ./.git -prune -o \
  -path ./juliet/cache -prune -o \
  -path ./juliet/raw -prune -o \
  -path ./juliet/build -prune -o \
  -path './traditional/dynamic/runs/*/cases' -prune -o \
  -type f -size +100M -print

find . -path ./.git -prune -o \
  -path ./juliet/cache -prune -o \
  -path ./juliet/raw -prune -o \
  -path ./juliet/build -prune -o \
  -path './traditional/dynamic/runs/*/cases' -prune -o \
  -type f -size +50M -printf '%s\t%p\n' | sort -rn | head
```

若使用 Git 索引（最可靠）：

```bash
git ls-files -z | xargs -0 -I{} sh -c \
  's=$(stat -c%s "{}"); [ "$s" -gt 52428800 ] && printf "%s\t%s\n" "$s" "{}"'
```

本机扫描（按 `.gitignore` 估算，2026-11-12，v2 后）：**约 248.1 MiB / 7,969 个文件**；最大单文件为 `traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl`（40.55 MB），**没有 >100 MB 文件**。这是估算，发布前仍以 `git ls-files` 为准。注意：本地 `juliet/cache/juliet-c-cplusplus-v1.3.zip` 为 146 MB，属于**未跟踪的下载缓存**；它出现在 `find` 结果里是正常的，只要不出现在 `git ls-files` 即可。

### 4.3 Secret scan

基础扫描（不打印命中内容，只列文件）：

```bash
grep -rIl -E 'sk-[A-Za-z0-9_-]{16,}|Bearer [A-Za-z0-9._-]{20,}' \
  --exclude-dir=.git --exclude-dir=raw --exclude-dir=cache \
  --exclude-dir=build --exclude-dir=cases --exclude-dir=__pycache__ .
```

本机结果：**无匹配文件**。再建议用独立工具：

```bash
gitleaks detect --source . --redact --no-banner
trufflehog filesystem . --only-verified
```

若没有安装，至少做一次 `git grep -nE 'api_key|token|secret|password'` 并人工确认每个命中都是字段名/说明，而不是值。

### 4.4 检查运行产物中的认证字段

```bash
grep -RIn --include='manifest.json' --include='config.json' \
  -E 'authorization|bearer|api_key_value_stored|authorization_header_stored' \
  runner/runs juliet_llm/runs hybrid/runs pair_joint/runs juliet_repair/runs evidence_prompt/runs | head -50
```

预期：只有 `api_key_value_stored: false`、`authorization_header_stored: false`、`api_key_present: true/false`，没有值。

### 4.5 检查盲评 private 目录

```bash
git check-ignore -v repair_eval/packages/repair_blind_v1/private/blind_key.json
```

预期：命中 `repair_eval/packages/*/private/`。若未命中，先修 `.gitignore`，不要把 key 加入索引。

### 4.6 检查 PDF/报告

```bash
pdfinfo report/report_extended_zh.pdf | head -8
pdffonts report/report_extended_zh.pdf | head

pdfinfo report/report_zh.pdf | head -8
pdffonts report/report_zh.pdf | head
```

预期：扩展版 27 页、基础版 17 页；字体嵌入；无缺字。报告正文不应包含 key、账号、内部 URL 凭证。

### 4.7 推送前最后一步

```bash
git diff --cached --stat
git diff --cached -- . ':!*.jsonl' ':!*.json' | head -200
```

确认没有把缓存、二进制或密钥加入索引。**不要使用 `git add -f` 绕过 `.gitignore`**，除非你明确知道该文件不含敏感信息且小于 100 MB。

---

## 5. 残余风险

| 风险 | 等级 | 说明/缓解 |
| --- | --- | --- |
| 同机进程读取环境变量 | 中 | 同一用户/容器内的进程可读 `/proc/<pid>/environ`；使用专用机器/容器，运行后 `unset` |
| Shell history 记录 key | 高 | 不要在命令行内联 key；使用 secret manager/环境注入；定期清理 history |
| 脱敏是模式匹配 | 中 | `sk-...`/`Bearer ...` 不是完整 DLP；新格式可能漏网；用独立 scanner 复核 |
| 本地绝对路径/用户名 | 低–中 | run manifests、审计和日志含 `/mnt/c/Users/tzh03/...`；私有仓库可接受，公开前应清理或重新生成相对路径 |
| 模型输出含上游代码/CVE | 低 | 研究产物；公开前核对上游许可；不要把模型输出当作事实 |
| `pair_joint` 1/180 注释含 CVE | 低 | 两侧相同注释，不指示漏洞侧；已在报告中记录，未改写源码 |
| 盲评 key 未公开 | 低 | 公开仓库无法复现解盲；汇总 `summary.json` 仍保留 |
| 大型结果文件 | 中 | 当前最大 40.55 MB；若新增结果 >100 MB，先压缩/拆分或使用 Git LFS（需显式配置） |
| 私有仓库协作者 | 中 | 只邀请必要人员；定期审查 access；泄露后轮换 key |
| 模型端点/价格变化 | 低 | 记录 run 日期与价格快照；不要把历史价格当长期报价 |
| 提示注入 | 低 | 模型不执行代码；但输出可能被代码注释影响，评测结果应按“模型 + 数据”解读 |

---

## 6. 如果 key 已经泄漏

1. **立即轮换** provider key（OpenCode Go / Xiaomi / DeepSeek），不要先清理仓库。
2. 在 provider 控制台撤销旧 key，检查用量/账单异常。
3. 从当前工作树删除文件，并确认 `.gitignore` 覆盖。
4. 如果已 commit 但未 push：`git reset`/`git commit --amend` 移除；如果已 push：使用 `git filter-repo` 重写历史，强制推送，并通知协作者重新 clone。
5. 在 GitHub 上删除/失效相关 artifact、release、Actions 日志；检查 fork/PR 引用。
6. 记录事件：时间、暴露范围、轮换时间、影响评估。不要把 key 写进 issue/PR 描述。

> 历史重写是破坏性操作；只有在确认泄漏且需要清除历史时执行，并先备份。

---

## 7. 数据与许可

- **SecVulEval**：`SecVulEval.xlsx` 为课程提供的上游数据集；`datasets/` 和 `splits/` 是派生数据。上游条款优先于本仓库说明。
- **Juliet**：NIST SARD 的 Juliet Test Suite for C/C++ v1.3；官方归档不随仓库分发，`fetch_juliet.py` 从 NIST 下载。使用/再分发请遵循 NIST SARD 页面条款。
- **模型输出**：由 provider 生成；可能包含上游代码片段、CVE 注释、函数名。仓库是私有研究仓库，公开化前应重新评估许可与泄露风险。
- **本仓库没有 LICENSE 文件**：在对外分发前补充合适的许可证，并确认与上游数据条款兼容。

---

## 8. 已执行的验证（2026-11-12）

| 检查 | 结果 |
| --- | --- |
| 文本文件 secret 模式扫描（`sk-...` / `Bearer ...`） | 0 个匹配文件 |
| 凭据形状文件名扫描 | 仅 `repair_eval/packages/repair_blind_v1/private/blind_key.json`（盲评 key，已加入 `.gitignore`） |
| `juliet_llm.selfcheck` | `no credential-shaped artefacts` PASS |
| manifest 字段抽查 | `api_key_value_stored=false`、`authorization_header_stored=false` |
| 按 `.gitignore` 估算的受控体积 | 约 248.1 MiB / 7,969 文件（v2 后估算）；最大 40.55 MB |
| >100 MB 文件 | 0 |
| `juliet/scripts/verify.py` | PASS（2,853 文件） |
| 动态/静态/盲评自检 | 见 `docs/REPRODUCIBILITY.md` §4.1 |

这些检查是**发布前的最低门槛**，不构成对历史提交的保证。若仓库已有多条历史，仍需对完整历史做一次扫描。
