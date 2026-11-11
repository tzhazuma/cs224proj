# GitHub 私有仓库发布指南（GITHUB_RELEASE）

> 状态：本目录已作为 **GitHub 私有仓库 `cs224proj`** 发布：<https://github.com/tzhazuma/cs224proj>。下文保留从零重建/复现发布的完整步骤。
> 运行环境：WSL Ubuntu 26.10 x86_64；项目根目录 `/mnt/c/Users/tzh03/Downloads/cs224proj`。
> 首次预检日期：2026-11-12。本文是发布工具/命令文档，**不替代** `docs/SECURITY.md` 的威胁模型和 `docs/REPRODUCIBILITY.md` 的复现说明。
>
> 命令中的 `<owner>`、`<org>`、`<base-commit>`、`<your-name>`、`path/to/secret` 等是占位符，复制前必须替换成实际值。

## 0. 当前结论

**发布状态：PUBLISHED（私有仓库已创建并推送：<https://github.com/tzhazuma/cs224proj>）。**

- `audit/final_audit.md`（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO，Overall `PASS_WITH_WARNINGS`**；must-fix 为空，发布门禁已通过（见 §2.1）。
- 本地项目已经是 Git 仓库：`origin` 指向 `https://github.com/tzhazuma/cs224proj.git`，当前分支 `main` 跟踪 `origin/main`；本次文档同步**没有执行 `git commit`/`git push`，也没有执行 `gh`**。
- `gh` 在首次预检时不在 `PATH`；`~/.config/gh` 已有登录配置（当时只检查存在性，**没有读取或打印任何认证文件**）。本次未重新验证 `gh` 安装状态；重建/换机时按第 4 节安装。
- 按 `.gitignore` 估算的待发布内容：**约 7,969 个文件 / 248.1 MiB**；最大单文件 40,554,155 字节（`traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl`），**没有 ≥100 MB 的文件**。这是 v2 后的估算，最终以暂存区 `git ls-files` 为准。
- 本文保留从零重建/复现发布的完整步骤；**当前仓库已存在，不要重复执行 §8.2 的 `gh repo create`**。日常更新只需 `git add`/`commit`/`push`（按第 6 节检查后）。

本文的命令全部在 **WSL** 中执行，不要用 Windows 的 Git Bash 初始化这个仓库，避免权限位和换行符混用。

---

## 1. 边界与禁止事项

本流程只创建版本控制元数据和 GitHub 私有仓库，**不重跑实验、不修改或覆盖任何原始实验结果**。

- 不运行会改写 `requests.jsonl`、`results.jsonl`、`manifest.json`、`metrics.json`、报告或冻结数据的脚本。
- 如确需重跑审计/实验，必须写入新的重跑目录（审计重跑直接覆盖 `audit/final_audit.{json,md}`，旧文件先备份到仓库外；其它实验写到新的 `repro_*` 目录），不得覆盖原始结果；这属于对应负责人的范围，不在本文执行。
- **不读取、不复制、不打印** `~/.config/gh` 下的认证文件；不运行 `gh auth token`；不把 token 写进 remote URL、命令行、日志、截图或提交信息。
- 不使用 `git add -f` 绕过 `.gitignore`。缓存、原始 Juliet 树、逐 case 二进制、请求缓存和盲评 `private/` 都不进仓库。
- `.gitignore` 只影响未跟踪文件；已经被 `git add` 的密钥不会因为补一条 ignore 而消失，必须从索引移除（`git reset` / `git rm --cached`）。
- 不把 `GH_TOKEN` / `GITHUB_TOKEN` 导出到共享 shell 或写进命令历史；优先使用 `gh auth login` 的 keyring。
- 私有仓库不是密钥保管库。密钥一旦进入任何 commit，即使后来删除，也仍然存在于历史中；必须按第 10 节先轮换再清理。
- 未经维护者明确同意，不执行 `gh repo delete`、历史重写或 force push。

---

## 2. 发布门禁（必须先通过）

### 2.1 Audit must-fix 清零

最新审计（2026-11-11T21:45:48Z）为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO**，Overall **`PASS_WITH_WARNINGS`**，must-fix 为空。原 5 个 must-fix 与新增检查的关闭证据如下：

| ID | 区域 | 修复与证据 | 状态 |
| --- | --- | --- | --- |
| C3 | prompt 泄漏 | `juliet_llm/cleaning.py` 的禁用模式/字符串清洗已覆盖 `benign`/`fixed`/`safe`/`clean`/`patched`/`remediated`；prompt 升到 `.2`；`juliet_llm/build/audit_report.md` 的 11 类计数全为 0，200/200 prompt 通过 | 已关闭 |
| D6 | hybrid 泄漏 | v2 输入包 `hybrid/inputs_v2` + 10 个 `hybrid_v2_*` run；1,400 条 v2 prompt 全通过，v1 的 6 个 good 单元保留为泄漏对照 | 已关闭 |
| I3 | repair 成本 | all-in 统一为 `$0.082550`（headline `$0.032831`；含 `parser_dev/mimo_test70_v1` 的 `$0.005034`），审计重算 delta `-0.000000318` | 已关闭 |
| I5 | 价格口径 | v2 的 DeepSeek 已按 `$0.15/$0.60/$0.003` 配置，10/10 run 与 provider `list_cost` 在 2% 内一致；v1 的高峰价 `$0.30/$1.20` 与 `analysis/cost_normalization.md` 的 off-peak/normalized 口径一并记录 | 已关闭 |
| L4 | 路径可复现 | `analysis/aggregation.json` 已用仓库内路径重生成，14/14 个 run 路径存在 | 已关闭 |
| L5 | v1 对照保留 | `hybrid_v1` 与 pre-leakfix 的 2 个 juliet_llm run 原样保留，作为泄漏对照；审计确认未被改写 | 已通过 |
| I7 | normalized 成本 | 79 个 run / 9,584 条请求；verification PASS，0 peak rows，0 changed source artifacts | 已通过 |

发布前只认**最新**审计结果：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
grep -n '^Overall:' audit/final_audit.md
grep -n '^Checks:' audit/final_audit.md
```

当前应看到 `Overall: **PASS_WITH_WARNINGS**`、`Checks: 58 PASS, 0 FAIL, 3 WARN, 1 INFO.`。由于 B5/D5/F4 是 WARN，**不要为了得到纯 `PASS` 删除 WARN 说明**；若出现新的 FAIL，停止。

- B5、D5、F4 是 WARN，不阻断发布，但不要删除它们在 README/报告中的说明。
- 审计脚本已切到 **v2 / postleakfix** 官方产物（`HYBRID_OFFICIAL=hybrid_v2`、`JULIET_OFFICIAL_RUNS=*_postleakfix`），并把 v1/pre-leakfix 作为历史对照检查；重跑时不需要再改脚本。
- 如果修复改动了代码、prompt 或结果文件，审计负责人必须在新工作树上重跑；本文不覆盖 `audit/final_audit.md`。重跑前把旧审计备份到**仓库外**，不要放进 `audit/`（`check_scope` 会因额外文件给出 N2 WARN）。

### 2.2 工作树冻结

在 commit 之前，不要再跑实验或生成新结果。发布提交应当对应审计所验证的那份**代码/结果工作树**；README/docs 的文字同步不改变被审计产物，但若改动了 `juliet_llm/build/`、`hybrid/*`、`audit/` 或任何 `results.jsonl`/`metrics.json`/报告数字，必须重新审计后再继续。

---

## 3. 环境预检（首次发布前 2026-11-12；仓库现已发布）

| 检查项 | 结果 |
| --- | --- |
| WSL | Ubuntu 26.10，x86_64 |
| `git` | 2.55.0 |
| `curl` | 8.20.0 |
| 项目根 `.git` | **存在**；当前分支 `main` 跟踪 `origin/main` |
| `origin` | `https://github.com/tzhazuma/cs224proj.git` |
| `gh` 在 `PATH` | 首次预检时不存在；本次文档同步未执行 `gh`，当前安装状态未重新验证 |
| `gh` 常见路径 | 首次预检时 `~/.local/bin/gh`、`~/bin/gh`、`/usr/local/bin/gh`、`/usr/bin/gh`、`/snap/bin/gh` 均不存在 |
| `~/.config/gh` | 存在；当时只检查存在性，未读取内容 |
| 官方 gh 验证 | v2.103.3 tarball SHA-256 通过；临时目录运行正常；`gh auth status` 成功；`ssh -T git@github.com` 认证成功 |
| Git 身份 | `user.name`、`user.email` 已设置（未打印具体值） |
| `/mnt/c` 的 `core.filemode` | 自动探测为 `false`；本文仍显式设置 |
| 符号链接 / 嵌套 `.git` | 未发现 |
| 可发布文件 | 约 7,969 个 / 248.1 MiB（v2 后估算；以 `git ls-files` 为准） |
| 最大单文件 | 40,554,155 B，`traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/results.jsonl` |
| ≥100 MB 文件 | 0 |
| 密钥样式文件名/内容 | 只打印文件名的扫描未发现命中 |
| `gitleaks` / `trufflehog` | 未安装；第 6 节给出等价的最小扫描 |

复现环境检查：

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
command -v gh || echo "gh not in PATH"
for p in "$HOME/.local/bin/gh" "$HOME/bin/gh" /usr/local/bin/gh /usr/bin/gh /snap/bin/gh; do
  [ -x "$p" ] && { echo "found: $p"; "$p" --version; }
done
git --version
curl --version | head -1
test -d .git && echo "git initialized" || echo "no .git (expected before section 5)"
test -f "$HOME/.config/gh/hosts.yml" && echo "gh config present" || echo "gh config absent"
```

> `~/.config/gh/hosts.yml` 只用于判断“是否已有登录配置”；不要 `cat`、不要 `cp`、不要提交。

---

## 4. `gh`：定位或安装到用户目录

### 4.1 先找现有 `gh`

```bash
command -v gh || true
for p in "$HOME/.local/bin/gh" "$HOME/bin/gh" /usr/local/bin/gh /usr/bin/gh /snap/bin/gh; do
  [ -x "$p" ] && "$p" --version
done
```

如果已有可用的 `gh`（版本不要太旧），直接跳到 4.3；不要为了“最新版”覆盖一个正在工作的安装。

### 4.2 官方二进制安装到 `~/.local/bin`

以下脚本**不需要 sudo**，只从 GitHub 官方 release 下载，先校验 SHA-256 再安装。当前预检验证过的版本是 v2.103.3；脚本会动态解析最新版。

```bash
set -euo pipefail

# 1) 版本：API 限流/403 时，可手动指定，例如 GH_VERSION=2.103.3
if [ -z "${GH_VERSION:-}" ]; then
  GH_VERSION="$(curl -fsSL -A 'Mozilla/5.0 (X11; Linux x86_64)' \
    https://api.github.com/repos/cli/cli/releases/latest \
    | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -n1)"
fi
[ -n "${GH_VERSION:-}" ] || { echo "无法解析 gh 版本；请手动设置 GH_VERSION" >&2; exit 1; }

# 2) 架构
case "$(uname -m)" in
  x86_64) GH_ARCH=amd64 ;;
  aarch64|arm64) GH_ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

# 3) 下载 + 校验（部分代理会对无 UA 的 curl 返回 403）
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/cli/cli/releases/download/v${GH_VERSION}"
ASSET="gh_${GH_VERSION}_linux_${GH_ARCH}.tar.gz"
UA='Mozilla/5.0 (X11; Linux x86_64)'
curl -fL --retry 3 -A "$UA" -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -fL --retry 3 -A "$UA" -o "$TMP/gh_${GH_VERSION}_checksums.txt" "$BASE/gh_${GH_VERSION}_checksums.txt"
(cd "$TMP" && grep -F "  $ASSET" "gh_${GH_VERSION}_checksums.txt" | sha256sum -c -)

# 4) 解压并安装到用户目录
tar -xzf "$TMP/$ASSET" -C "$TMP"
install -d "$HOME/.local/bin"
install -m 0755 "$TMP/gh_${GH_VERSION}_linux_${GH_ARCH}/bin/gh" "$HOME/.local/bin/gh"
"$HOME/.local/bin/gh" --version
```

说明：

- 校验行必须显示 `OK`；校验失败就停止，不要安装。
- 不要从第三方镜像、网盘或来历不明的 `gh` 二进制安装。
- 若 `curl` 仍返回 403，先确认代理/网络策略；也可以在有浏览器的 Windows 侧从 <https://github.com/cli/cli/releases> 下载同名 tarball 和 `checksums.txt`，复制到 WSL 后按上面的 `sha256sum -c` 校验。
- 如果 `sha256sum -c` 报 “FAILED open or read”，通常是把 tarball 存成了别的文件名；必须保持 release asset 的原始文件名。

### 4.3 让 `~/.local/bin` 进入 `PATH`

```bash
export PATH="$HOME/.local/bin:$PATH"
hash -r
command -v gh
gh --version
```

需要持久化时，把下面一行加入 `~/.bashrc`（只加一次）：

```bash
grep -qxF 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null \
  || printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
```

新开 shell 后仍找不到 `gh`，就直接用绝对路径 `"$HOME/.local/bin/gh"`。

### 4.4 验证登录（不显示密钥）

```bash
gh auth status --hostname github.com
ssh -T git@github.com
```

预期：`gh auth status` 返回 0，显示已登录；`ssh -T` 显示 `Hi <account>! You've successfully authenticated...`。`gh auth status` 会把 token 掩码显示；**不要把它的输出贴到公开渠道**。

当前预检的登录配置使用 **SSH** 协议，且 `ssh -T` 已成功。若 SSH 不可用，改用 HTTPS：

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git
gh auth status --hostname github.com
```

`--web` 流程只在浏览器输入一次性代码，不要把 token 粘到命令行。**禁止** `gh auth token`、`cat ~/.config/gh/hosts.yml`、`cp -r ~/.config/gh .`。

---

## 5. 初始化 Git 并暂存

> 状态：仓库已初始化并推送。本节仅用于从零重建/换机；已有 `.git` 时不要重新 `git init`，日常更新按第 6 节检查后 `git add`/`commit`/`push`。

### 5.1 初始化与本地配置

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
if [ -d .git ]; then
  echo "already a git repository; skip git init"
else
  git init -b main
fi

# /mnt/c 是 DrvFs：关闭 filemode，避免所有文件被记成 100755
git config --local core.filemode false
git config --local core.autocrlf false

git config --get user.name
git config --get user.email
```

如果 `user.name` / `user.email` 为空，先设置本地身份（不要编造别人的邮箱）：

```bash
git config --local user.name "<your-name>"
git config --local user.email "<your-github-noreply-email>"
```

### 5.2 先 dry-run，确认没有缓存混入

```bash
git add -n . | wc -l
git add -n . | sed -n '1,40p'
```

检查输出中不应出现这些路径：

- `juliet/cache/`、`juliet/raw/`、`juliet/build/`
- `traditional/dynamic/runs/*/cases/`、`traditional/dynamic/runs/*/support/`
- `**/runs/*/cache/`
- `repair_eval/packages/*/private/`
- `__pycache__/`

`juliet_llm/build/` 是**故意保留**的 prompt 输入和泄漏审计，不是编译产物，应当进入提交。

### 5.3 正式暂存

```bash
git add .
git status --short | wc -l
git status --ignored --short | sed -n '1,40p'
git diff --cached --stat | tail -20
git ls-files | wc -l
```

预期：`git status --ignored` 中被忽略的缓存显示为 `!!`，而不是 `A`。如果发现缓存/私钥被暂存，先 `git reset`（只取消暂存，不删工作树），修好 `.gitignore` 或路径后重新 `git add .`；**不要**用 `git add -f`。

---

## 6. 大文件与密钥检查（针对暂存区）

以下检查全部基于 `git ls-files`（索引），比 `find` 更接近真正会推送的内容。

### 6.1 阻断项：单文件 ≥100 MB

GitHub 单文件硬上限是 100 MB。发布前必须为空：

```bash
git ls-files -z | while IFS= read -r -d '' f; do
  s=$(stat -c '%s' -- "$f")
  if [ "$s" -ge 100000000 ]; then
    printf '%s\t%s\n' "$s" "$f"
  fi
done
```

预期无输出。若命中，停止：先 `git reset`，把该文件加入 `.gitignore` 或改用外部存储；本仓库没有配置 Git LFS，不要临时 `git lfs track` 了事。

### 6.2 复核：最大的 20 个文件和总体积

```bash
git ls-files -z | while IFS= read -r -d '' f; do
  s=$(stat -c '%s' -- "$f")
  printf '%s\t%s\n' "$s" "$f"
done | sort -rn | head -20

git ls-files -z | xargs -0 -r stat -c '%s' \
  | awk '{s+=$1} END {printf "files=%d bytes=%d MiB=%.1f\n", NR, s, s/1048576}'
```

当前基线：约 7,969 个文件、248.1 MiB（v2 后估算，以暂存区为准）；最大 40.55 MB。若数字明显变化，先查明原因再提交。首次发布只做一个初始 commit；不要反复提交重新生成的大 JSONL，Git 历史会累积体积。

### 6.3 密钥样式文件名

```bash
git ls-files | grep -Ei '(^|/)(\.env|id_rsa|id_ed25519|hosts\.yml)|\.(pem|key|p12|pfx)$' \
  | grep -v '\.env\.example$' || echo "no secret-like filenames"
```

预期 `no secret-like filenames`。`.env.example` 是允许的模板；`*.key` 若确实是代码 fixture，也必须人工确认内容不含真实密钥。

### 6.4 密钥样式内容（只打印文件名）

```bash
git grep --cached -Il -E \
  'sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|[Aa]uthorization: *[Bb]earer [A-Za-z0-9._-]{20,}' \
  -- . || echo "no secret-like content"
```

预期 `no secret-like content`。`-I` 跳过二进制，`-l` 只输出文件名，避免把命中内容打印到终端或聊天。若命中，**不要直接在公开渠道贴命中行**；先在私有终端人工判断，再决定移除/轮换。

### 6.5 盲评 `private/` 必须被忽略

```bash
git check-ignore -v repair_eval/packages/repair_blind_v1/private/blind_key.json
git ls-files --error-unmatch \
  repair_eval/packages/repair_blind_v1/private/blind_key.json 2>/dev/null \
  && echo "STOP: private key is staged" \
  || echo "not staged (expected)"
```

预期第一行命中 `.gitignore` 的 `repair_eval/packages/*/private/`，第二行输出 `not staged (expected)`。不要在终端打印 `blind_key.json` 的内容。

再确认所有 private 目录都没有进入索引：

```bash
git ls-files | grep -E '^repair_eval/packages/[^/]+/private/' \
  && echo "STOP: private files tracked" \
  || echo "no private files tracked"
```

### 6.6 `.gitignore` 覆盖检查

```bash
git check-ignore -v \
  juliet/cache/ \
  juliet/raw/ \
  juliet/build/ \
  traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/cases/ \
  repair_eval/packages/repair_blind_v1/private/blind_key.json
```

预期分别命中 `.gitignore` 中的 `juliet/cache/`、`juliet/raw/`、`juliet/build/`、`traditional/dynamic/runs/*/cases/`、`repair_eval/packages/*/private/`。本次已用临时仓库验证过这些模式和 `juliet_llm/build/` 的“保留”行为。

再直接检查索引，防止“已被跟踪、ignore 不再生效”的情况：

```bash
git ls-files | grep -E '^(juliet/(cache|raw|build)|traditional/dynamic/runs/[^/]+/(cases|support)|.*/runs/[^/]+/cache|repair_eval/packages/[^/]+/private)/' \
  && echo "STOP: ignored paths are tracked" \
  || echo "no ignored paths tracked (expected)"
```

### 6.7 可执行位检查

```bash
git ls-files -s | awk '$1=="100755" {sub(/^[^ \t]+ [^ \t]+ [^ \t]+\t/, ""); print}' | wc -l
git ls-files -s | awk '$1=="100755" {sub(/^[^ \t]+ [^ \t]+ [^ \t]+\t/, ""); print}' | sed -n '1,20p'
```

预期只有确实需要执行的脚本。若几乎所有文件都是 `100755`，说明 `/mnt/c` 的权限位被带进来了：停止提交，确认 `core.filemode=false`，取消暂存后重新 `git add .`；必要时对已有索引项执行 `git update-index --chmod=-x`。

### 6.8 绝对路径（非阻断，但要知道）

```bash
git grep --cached -Il '/mnt/c/Users/' -- . | wc -l
```

私有仓库可以接受本机绝对路径；如果以后要公开，先清理或重新生成这些记录。不要把这一项误当成密钥泄漏。

### 6.9 可选的独立扫描器

当前 WSL 未安装 `gitleaks` / `trufflehog`。如果已安装，可在 commit 后追加：

```bash
command -v gitleaks >/dev/null && gitleaks detect --source . --redact --no-banner
command -v trufflehog >/dev/null && trufflehog filesystem . --only-verified
```

`--redact` 很重要；不要把未脱敏的扫描输出贴到 issue/PR。

### 6.10 阻断条件汇总

出现以下任一情况，**不要 commit、不要建库、不要 push**：

- 任何 ≥100 MB 的暂存文件；
- 任何密钥样式内容或密钥样式文件名；
- `repair_eval/packages/*/private/` 被跟踪；
- `juliet/cache/`、`juliet/raw/`、`juliet/build/`、`*/cases/`、`*/support/`、`**/runs/*/cache/` 被跟踪；
- 大量 `100755` 权限位；
- 审计 must-fix 未清零。

---

## 7. 首次提交

确认第 6 节全部通过后：

```bash
git commit -m "Initial commit: CS224 vulnerability evaluation artifacts"
git show --stat --oneline HEAD | sed -n '1,20p'
git rev-parse HEAD
```

记录 `git rev-parse HEAD` 的 40 位 SHA，填入第 9 节。

- 若 commit 因 GPG 签名失败：先确认策略；当前预检 `commit.gpgsign` 未设置。不要在未确认的情况下长期使用 `--no-gpg-sign`。
- 若 pre-commit hook 修改了文件：重新执行第 6 节检查，再提交。
- 不要用 `git commit --no-verify` 绕过检查，除非维护者明确同意。

---

## 8. 创建私有仓库并首次推送（当前已完成；以下仅从零重建）

> 状态：**已完成**。私有仓库 <https://github.com/tzhazuma/cs224proj> 已创建并推送，`origin` 指向 `https://github.com/tzhazuma/cs224proj.git`。日常更新不要执行本节，只需 `git add`/`commit`/`push`；以下命令保留给灾备或从零重建。**当前仓库上不要执行 8.2 的 `gh repo create`**，否则会因 `origin` 已存在而失败或重复建库。

### 8.1 建库前预检

```bash
gh auth status --hostname github.com
git status --porcelain
git branch --show-current
git remote -v

if gh repo view cs224proj --json nameWithOwner,visibility,url 2>/dev/null; then
  echo "STOP: repository already exists"
else
  echo "repository not found (rebuild-only)"
fi
```

- 当前状态：`gh repo view` 应显示仓库已存在（走 `STOP` 分支）；`origin` 已指向 `https://github.com/tzhazuma/cs224proj.git`。
- 确认 `gh auth status` 的 active account 就是目标账号；如果不是，先切换账号，不要建到别人的名下。
- 从零重建时 `git status --porcelain` 必须为空；当前仓库若有未提交的文档改动，先按维护者流程提交，不要直接重建。
- 当前分支必须是 `main`；不是的话先 `git branch -M main`（仅在尚未推送时）。
- **从零重建时** `git remote -v` 应为空；当前已有 `origin`，不要重复建库。
- 若目标仓库在组织下，本节以及 8.3/8.4 中的 `cs224proj` 都要写成 `<org>/cs224proj`。

### 8.2 创建私有仓库并推送（仅从零重建）

个人账号下：

```bash
gh repo create cs224proj --private --source=. --remote=origin --push
```

组织下（把 `<org>` 换成组织名）：

```bash
gh repo create <org>/cs224proj --private --source=. --remote=origin --push
```

这条命令会：创建 **private** 仓库、把 `origin` 指向它、推送当前 `main`。不要加 `--public`；不要用 `--push` 之前跳过第 6 节。**当前仓库已存在，不要执行本节的 create。**

### 8.3 推送后验证

```bash
gh repo view cs224proj --json nameWithOwner,visibility,url,defaultBranchRef
git remote -v
git status -sb
git ls-remote --heads origin
```

预期：

- JSON 中 `"visibility":"PRIVATE"`；
- `git status -sb` 显示 `## main...origin/main`；
- `git ls-remote --heads origin` 只有 `refs/heads/main`；
- `git remote -v` 的 URL 是 `git@github.com:<owner>/cs224proj.git` 或 `https://github.com/<owner>/cs224proj.git`，**不含 token、用户名密码或 `x-access-token`**。

确认忽略路径没有进入 HEAD：

```bash
git ls-tree -r --name-only HEAD \
  | grep -E '^(juliet/(cache|raw|build)|traditional/dynamic/runs/[^/]+/(cases|support)|.*/runs/[^/]+/cache|repair_eval/packages/[^/]+/private)/' \
  && echo "STOP: ignored paths are tracked" \
  || echo "ignored paths absent (expected)"
```

### 8.4 推送失败时

**不要**因为 push 失败就重复执行 `gh repo create`；先判断仓库是否已经创建：

```bash
gh repo view cs224proj --json nameWithOwner,visibility,url
```

- **SSH 失败**（`Permission denied (publickey)`）：先 `ssh -T git@github.com`。如果 SSH 不可用，改用 HTTPS：

```bash
git remote set-url origin https://github.com/<owner>/cs224proj.git
gh auth setup-git
git push -u origin main
```

- **仓库已创建但 push 失败**：不要重建；修复认证后 `git push -u origin main`。
- **分支不是 main**：仅在尚未推送时 `git branch -M main`，然后 `git push -u origin main`。
- **网络/代理失败**：确认 `github.com`、`api.github.com`、`codeload.github.com` 可访问；不要把含密码的代理 URL 写进 remote 或文档。

### 8.5 可选：新鲜 clone 复核

如果需要确认远端内容与本地一致（会下载约 237 MB）：

```bash
TMP="$(mktemp -d)"
git clone --depth 1 "$(git remote get-url origin)" "$TMP/cs224proj"
cd "$TMP/cs224proj"
git ls-files | wc -l
for p in juliet/cache juliet/raw juliet/build \
         repair_eval/packages/repair_blind_v1/private; do
  [ -e "$p" ] && echo "UNEXPECTED: $p"
done
cd - >/dev/null
rm -rf "$TMP"
```

预期 clone 成功、文件数与本地一致、`UNEXPECTED` 无输出。

---

## 9. 发布记录

发布已完成。在私有发布记录中保存以下字段（不要把 token、账号密码或认证文件内容写进去）：

```bash
date -u +%Y-%m-%dT%H:%M:%SZ
git rev-parse HEAD
gh repo view cs224proj --json nameWithOwner,visibility,url,defaultBranchRef
gh --version
```

当前记录：

| 字段 | 值 |
| --- | --- |
| UTC 时间 | 2026-11-12（发布已完成；精确时间以 GitHub/commit 记录为准） |
| commit SHA | 见仓库 `HEAD`（本文档不复制 SHA，避免与后续提交不一致） |
| 仓库 URL | <https://github.com/tzhazuma/cs224proj> |
| visibility | `PRIVATE` |
| audit 时间 / Overall | 2026-11-11T21:45:48Z / `PASS_WITH_WARNINGS`（58 PASS / 0 FAIL / 3 WARN / 1 INFO） |
| gh 版本 | 首次预检为 v2.103.3（临时目录校验；当前安装状态未重新验证） |
| 操作者 | 仓库维护者 |

标签（tag）、GitHub Release、Actions、制品上传不在本文范围；需要时另写流程，不要在本流程里顺带创建。

标签（tag）、GitHub Release、Actions、制品上传不在本文范围；需要时另写流程，不要在本流程里顺带创建。

---

## 10. 事故处理

### 10.1 密钥在暂存区/工作树，但还没 commit

1. `git reset` 取消暂存；
2. 从工作树删除密钥，或把路径加入 `.gitignore`；
3. 如果密钥已经暴露给任何外部方，先轮换；
4. 重新执行第 6 节。

### 10.2 已 commit，但还没 push

如果密钥只出现在**最新一次** commit：

```bash
git rm --cached path/to/secret        # 只从索引移除；要同时删除工作树文件就用 git rm
git commit --amend --no-edit
```

如果密钥出现在更早的 commit：

```bash
git rebase -i <base-commit>           # 在编辑器中删除/修改对应 commit
# 或（更彻底）git filter-repo --path path/to/secret --invert-paths
```

这些操作只改写本地未推送的历史，不需要 force push。完成后重新执行第 6 节。不要用“再 commit 一次删除”来假装删除，旧 commit 里仍然有密钥。确认不再需要旧 reflog 时，可再执行 `git reflog expire --expire=now --all && git gc --prune=now` 清理本地对象。

### 10.3 已 push

1. **先轮换密钥**，再清理历史；
2. 用 `git filter-repo` 等工具重写历史；
3. 用 `--force-with-lease` 推送，并通知所有协作者重新 clone；
4. 检查 GitHub 上的缓存/PR/fork 引用；必要时联系 GitHub Support。

不要在未轮换、未通知的情况下直接 force push。

### 10.4 仓库可见性错误

如果误建为 public：

```bash
gh repo edit cs224proj --visibility private --accept-visibility-change-consequences
```

或立即在 GitHub **Settings → General → Danger Zone** 改为 private。改为 private 不能撤回已经发生的暴露；按 10.3 处理密钥。

### 10.5 误建仓库

`gh repo delete` 是破坏性操作，可能还需要额外 scope。除非维护者明确同意，不要执行。

---

## 11. 最终检查清单

- [x] 最新 `audit/final_audit.md` 为 **58 PASS / 0 FAIL / 3 WARN / 1 INFO**、Overall `PASS_WITH_WARNINGS`；C3/D6/I3/I5/L4 全部关闭
- [x] `audit/run_final_audit.py` 已按 `hybrid_v2` / `*_postleakfix` 官方产物运行（脚本已切到 v2，无需再改）
- [x] B5/D5/F4 等 WARN 的说明仍保留在报告中
- [ ] `gh --version` 正常，`gh auth status` 返回 0（本次未执行 `gh`，未重新验证）
- [ ] SSH 或 HTTPS 至少一种推送方式可用
- [ ] `git init -b main` 完成，`core.filemode=false`、`core.autocrlf=false`
- [ ] `git add -n` 和 `git status --ignored` 没有缓存/私钥
- [ ] 暂存区无 ≥100 MB 文件
- [ ] 暂存区无密钥样式文件名/内容
- [ ] `repair_eval/packages/*/private/` 未被跟踪
- [ ] 没有大量 `100755`
- [x] commit 完成并推送；发布 URL 为 <https://github.com/tzhazuma/cs224proj>
- [x] `gh repo create --private --source=. --remote=origin --push` 已完成（当前仓库不要重复执行）
- [x] 仓库 visibility 记录为 `PRIVATE`
- [x] `git remote -v` 的 URL 为 `https://github.com/tzhazuma/cs224proj.git`，不含 token
- [x] `git status -sb` 显示 `main...origin/main`
- [x] 发布记录已填写（§9）

---

## 附：最短路径（确认门禁已过后）

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj
export PATH="$HOME/.local/bin:$PATH"

[ -d .git ] || git init -b main
git config --local core.filemode false
git config --local core.autocrlf false
git add .
# 先执行第 6 节全部检查
git commit -m "Initial commit: CS224 vulnerability evaluation artifacts"

gh auth status --hostname github.com
gh repo create cs224proj --private --source=. --remote=origin --push
gh repo view cs224proj --json nameWithOwner,visibility,url,defaultBranchRef
```

如果 `gh` 还不在 `PATH`，先完成第 4 节；不要用 `sudo` 安装到系统目录，也不要把 `~/.config/gh` 复制进仓库。
