# 传统动态内存泄漏评估（CWE-401）

本目录只负责 **传统动态分析** 这一条腿：把真实 C/C++ 程序编译成可执行文件，在真实进程中运行，用 **LeakSanitizer/ASan** 和 **Valgrind Memcheck** 的实际输出判定是否存在内存泄漏，并输出统一的 JSONL 与 metrics。

- 不实现静态分析，不修改 `traditional/static/`。
- 不调用任何 LLM，不读取旧 LLM 结果，不覆盖 `runner/runs/` 下的旧实验。
- **判定标签只来自运行时证据**；函数名、文件名、注释都不参与预测。
- 真实数据来自 `juliet/`（Juliet C/C++ v1.3 CWE-401 子集），本目录只读该数据，不修改。

## 1. 环境与工具可用性（本机 WSL 实测）

| 项目 | 结果 |
|---|---|
| 系统 | WSL2，`Linux 6.18.58.1-microsoft-standard-WSL2` |
| CPU / Python | 16 vCPU；Python 3.14.8 |
| C 编译器 | `/usr/bin/gcc`，GCC 15.3.0 |
| C++ 编译器 | `/usr/bin/g++`，GCC 15.3.0 |
| clang/clang++ | 22.1.8（可用，默认未使用） |
| ASan/LSan | 可用；真实泄漏程序能被 LSan 报告，退出码 23 |
| Valgrind | **PATH 中没有**；本次验证/正式运行使用本地解包的 Valgrind 3.27.1（仅 `/tmp`，未打包进仓库） |

### 1.1 工具检查

```bash
python3 run_dynamic_eval.py check-tools --json
```

该命令会真实编译并运行一个泄漏程序和一个干净程序，而不是只查 `--version`。本机结果：

- `asan.available=true`，泄漏程序 `leak_detected=true`，`exit_code=23`；干净程序 `clean_detected=true`。
- `valgrind` 在 PATH 中缺失时，`valgrind.available=false`，但 ASan 检查仍通过。

### 1.2 没有 sudo 时使用 Valgrind

系统包未安装时，可以下载 `.deb` 并解包到临时目录（不需要 root）：

```bash
cd /tmp
apt-get download valgrind
mkdir -p /tmp/valgrind-root
dpkg-deb -x valgrind_*.deb /tmp/valgrind-root

VALGRIND_LIB=/tmp/valgrind-root/usr/libexec/valgrind \
python3 /path/to/cs224proj/traditional/dynamic/run_dynamic_eval.py \
  check-tools --valgrind-bin /tmp/valgrind-root/usr/bin/valgrind
```

正式运行同样通过 `--valgrind-bin` 和 `VALGRIND_LIB` 使用这个二进制；产物中记录了实际路径和版本。若系统已安装 Valgrind，直接省略 `--valgrind-bin` 即可。

## 2. 数据

- 数据集：Juliet Test Suite for C/C++ v1.3，`CWE401_Memory_Leak` 子集。
- 来源与哈希：`juliet/provenance.json`（官方 NIST SARD ZIP 的 SHA-256、解压清单）。
- 规模：`juliet/raw/testcases/CWE401_Memory_Leak` 下 2710 个 `.c/.cpp` 文件，其中 1660 个是带 `main` 的根用例；其余是多文件流变体的辅助翻译单元。
- 发现结果：**3316 个 case**（1658 个 bad / 1658 个 good 变体）。
- `w32` 用例被排除（Windows API，Linux 无法编译）；`wchar_t` 用例默认保留，可用 `--exclude-wchar` 排除。
- 数据目录不是本模块生成的；本模块只读取。正式运行的 `manifest.json` 记录 provenance 路径与 SHA-256。

## 3. 方法

### 3.1 用例发现与标签（不猜函数名）

Juliet 根用例的判定：

1. 源文件包含 `#ifdef INCLUDEMAIN`，且包含 `int main(`。
2. 对多文件流变体（如 `_22a`/`_22b`、`_62a`/`_62b`、`_81a`/`_81_bad`），按“数字模板号前缀”把同一组 `.c/.cpp` 一起编译。分组只使用文件名结构。
3. 用 Juliet 的预处理宏选择路径：
   - `-DOMITGOOD`：只保留 bad 路径，`expected_label=1`；
   - `-DOMITBAD`：只保留 good 路径，`expected_label=0`；
   - 只有单个宏的 `_bad`/`_good1` 文件按实际宏只生成一个变体；
   - 两者都没有时 `expected_label=null`，指标中排除。
4. `expected_label` 来自数据集的预处理结构，**不是**从函数名推断；预测只来自 LSan/Valgrind 的运行时证据。

### 3.2 编译

每个 case 独立编译，不共享全局二进制：

```text
gcc/g++ -g -O0 -fno-omit-frame-pointer -w -std=gnu11|gnu++14
        -fsanitize=address        # ASan/LSan 变体
        -DINCLUDEMAIN [-DOMITGOOD|-DOMITBAD]
        -I<juliet/testcasesupport> -I<case dir>
        <root 及同组翻译单元>
        <io.o> <std_thread.o>
        -lm -pthread -o case.asan
```

- `io.o` / `std_thread.o` 由 `juliet/raw/testcasesupport` 统一编译一次，避免每个 case 重复编译支持库。
- Valgrind 使用同一 source 的**非 ASan** 构建（`case.native`），因为 ASan 与 Valgrind 不能同时工作。
- 编译超时、编译错误、链接错误、缺头文件分别分类。
- 编译日志和完整 stderr 保留在 case 目录；JSONL 中只放截断预览。

### 3.3 执行与超时

- 每个进程独立进程组；超时向整个进程组发 `SIGKILL`，避免子进程残留。
- 默认单 case 超时 10s；编译默认 120s；Valgrind 超时 = `case_timeout × factor`（默认 ×3）。
- 记录退出码、信号、耗时、stdout/stderr、ASan/Valgrind 证据路径。
- `stdin` 默认 `/dev/null`，manifest 可覆盖；`argv`/`cwd`/`env` 均可配置。

### 3.4 ASan/LSan 证据

```text
ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=23:print_summary=1:log_path=<case>/logs/asan
LSAN_OPTIONS=exitcode=23
```

- 报告写到 `logs/asan.<pid>`，同时兼容直接写到 stderr 的情况。
- 解析 `ERROR: LeakSanitizer: detected memory leaks`、`Direct leak`、`Indirect leak`、`SUMMARY: AddressSanitizer: N byte(s) leaked`。
- 同时识别非泄漏 ASan 错误（`heap-use-after-free`、`bad-free`、`SEGV` 等）；出现这类错误时，该 case 的 ASan 判定为 `inconclusive`，除非同时解析到泄漏证据。
- **退出码 23 不作为泄漏的唯一依据**；真实 LSan 报告的退出码在不同选项/运行方式下可能变化，解析器以文本/XML 证据为准。

### 3.5 Valgrind 证据

```text
valgrind --tool=memcheck --leak-check=full \
  --show-leak-kinds=definite,indirect,possible \
  --errors-for-leak-kinds=definite --error-exitcode=99 \
  --xml=yes --xml-file=<case>/logs/valgrind.xml \
  --log-file=<case>/logs/valgrind.log --num-callers=20 ...
```

- 解析 XML 的 `<error>`：`Leak_DefinitelyLost` / `Leak_IndirectlyLost` / `Leak_PossiblyLost` / `Leak_StillReachable`。
- **阳性只计 `Leak_DefinitelyLost`**（CWE-401 的标准动态泄漏语义）；`StillReachable`（例如全局指针仍可达）单独记录，不算阳性。
- 同时解析 `<fatal_signal>`、`<status><exitcode>` 和非泄漏 Memcheck 错误（如 `InvalidFree`）。
- XML 缺失或解析失败 → detector `error`，不是 `clean`。

### 3.6 判定规则

每个 detector 独立给出：

- `leak`：解析到泄漏证据（LSan 任意 direct/indirect；Valgrind definite）。
- `clean`：进程正常结束（退出码 0，无信号/超时），且没有泄漏证据。
- `inconclusive`：超时、崩溃、非零退出但无泄漏、ASan 非泄漏错误、Valgrind 非泄漏错误、工具错误等。
- `unavailable`：工具不可用或 smoke test 失败。
- `not_run`：构建失败，未能执行。

case 级合并规则：

1. 任一 detector 报 `leak` → `outcome=leak`（敏感性优先）。
2. 否则，任一 detector 给出 `clean` → `outcome=clean`（至少一条正常完成的 no-leak 证据）。
3. 否则按 `build_failed` / `timeout` / `unavailable` / `inconclusive` 归类。
4. 只有 `leak`/`clean` 进入 TP/FP/TN/FN；其余计入 `inconclusive` 等，不进入混淆矩阵。

> `clean` 的含义是“至少一个动态检测器正常执行且没有报泄漏”，不是“数学上证明程序永不泄漏”。

## 4. 输入格式

### 4.1 Juliet 目录

```bash
python3 run_dynamic_eval.py run \
  --juliet-root /path/to/juliet/raw/testcases/CWE401_Memory_Leak \
  --support-dir /path/to/juliet/raw/testcasesupport \
  --out runs/my_run --run-id my_run \
  --detectors asan,valgrind --jobs 8
```

`--support-dir` 省略时自动找 `--juliet-root/../../testcasesupport`。

### 4.2 显式 JSONL manifest

每行一个 case：

```json
{"case_id":"demo-leak","source":"demo.c","expected_label":1,"timeout_s":10}
{"case_id":"demo-clean","source":"demo.c","expected_label":0,"argv":[]}
```

字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| `case_id` | 否 | 省略时按 source 生成；同一 manifest 内必须唯一 |
| `source` | 是 | 主源文件，相对路径按 manifest 所在目录解析 |
| `sources` | 否 | 多文件编译时的完整列表；缺省为 `[source]` |
| `language` | 否 | `c` / `cpp`；按扩展名推断 |
| `expected_label` | 否 | `1`/`0`，或 `vulnerable`/`clean`；缺省 null |
| `defines` / `include_dirs` / `cflags` / `ldflags` | 否 | 追加编译参数 |
| `argv` / `stdin` / `cwd` / `env` | 否 | 运行参数 |
| `timeout_s` | 否 | 默认 10 |
| `origin` / `variant` / `feature` / `metadata` | 否 | 分组与溯源字段 |

`source` 所在目录会自动加入 `-I`，方便相对 include。

## 5. 输出

每次运行必须使用**新的空目录**；已有非空目录会直接报错，避免覆盖旧结果。默认输出到 `traditional/dynamic/runs/<run_id>/`。

```text
runs/<run_id>/
├── cases.jsonl              # 实际执行的 case 清单（相对项目路径）
├── manifest.json            # 工具版本、输入哈希、配置、限制、结果哈希
├── results.jsonl            # 统一 JSONL，每行一个 case
├── results.partial.jsonl    # 运行中的增量文件（完成后删除）
├── metrics.json             # 混淆矩阵、召回/FPR、分层、失败分类
├── metrics.md               # 人读版
├── run.log                  # 时间戳进度与警告
├── support/                 # io.o / std_thread.o 及编译日志
└── cases/<case_id>/
    ├── case.asan            # ASan 二进制
    ├── case.native          # Valgrind 用非 ASan 二进制
    └── logs/
        ├── build_asan.log / build_asan.stderr
        ├── build_native.log / build_native.stderr
        ├── run_asan.stdout / run_asan.stderr / asan.<pid>
        ├── run_valgrind.stdout / run_valgrind.stderr
        ├── valgrind.xml / valgrind.log
```

`results.jsonl` 主要字段：

| 字段 | 说明 |
|---|---|
| `case_id`, `source`, `sources`, `source_sha256` | 用例与源码溯源 |
| `expected_label`, `label_source` | 数据标签与来源 |
| `outcome` | `leak` / `clean` / `build_failed` / `timeout` / `inconclusive` / `unavailable` |
| `detected_label` | 1 / 0 / null |
| `failure_class` | `compile.compiler_error`、`compile.link_error`、`runtime.timeout`、`runtime.signal:SIGSEGV`、`runtime.asan_error:bad-free` 等 |
| `runtime_class` | `exited_zero`、`exited_nonzero`、`signal:*`、`timeout`、`not_run` |
| `detectors.asan` / `detectors.valgrind` | build、execution、status、leak_detected、leaked_bytes、evidence、notes、artifacts |
| `evidence_summary` | 每个 detector 的判定摘要 |

`metrics.json` 的混淆矩阵方向与项目其他结果一致：`[[TN, FP], [FN, TP]]`，正类是 vulnerable。指标包含 TP/FP/TN/FN、precision、recall、FPR、specificity、accuracy、F1、recall/FPR 的 Wilson 95% CI，以及按 language/origin/variant/feature 分层。

## 6. 运行命令

```bash
cd /mnt/c/Users/tzh03/Downloads/cs224proj/traditional/dynamic

# 1) 工具真实自检
python3 run_dynamic_eval.py check-tools --json

# 2) 真实临时程序自测（自动清理；不产生正式结果）
python3 run_dynamic_eval.py selftest --jobs 2
# 有本地 Valgrind 时：
VALGRIND_LIB=/tmp/valgrind-root/usr/libexec/valgrind \
python3 run_dynamic_eval.py selftest --jobs 2 \
  --valgrind-bin /tmp/valgrind-root/usr/bin/valgrind

# 3) 只发现 case，不编译
python3 run_dynamic_eval.py discover \
  --juliet-root /path/to/CWE401_Memory_Leak \
  --out /tmp/juliet_cases.jsonl

# 4) 小规模试跑
python3 run_dynamic_eval.py run \
  --juliet-root /path/to/CWE401_Memory_Leak \
  --out /tmp/cwe401_pilot --run-id cwe401_pilot \
  --max-cases 40 --jobs 4 --detectors asan,valgrind
```

## 7. 验证记录

### 7.1 真实临时小程序自测

`selftest` 在 `tempfile.mkdtemp()` 中动态生成并真实编译/运行以下程序，结束后删除：

| 程序 | 预期 | 实测 |
|---|---|---|
| `malloc` 未 `free` | leak | leak |
| `malloc` + `free` | clean | clean |
| 条件泄漏（无参数） | clean | clean |
| 同一程序带 `argv=leak` | leak | leak（证明不是按源码静态猜） |
| C++ `new[]` 未 `delete[]` | leak | leak |
| 语法错误 | build_failed / compile.* | 通过 |
| 无限循环 | timeout | 通过 |
| 空指针写入 | inconclusive + runtime.* | 通过 |
| Juliet 风格 `OMITGOOD`/`OMITBAD` | bad=1 / good=0 | 通过 |
| Valgrind 泄漏/干净 | leak / clean，XML definite | 通过 |

`SELFTEST PASSED`，临时目录已自动清理。

### 7.2 真实 Juliet 试跑

- 200 个 case，ASan-only，8 workers：
  - 94 TP / 0 FP / 100 TN / 4 FN / 2 inconclusive
  - recall 0.9592，FPR 0.0
  - 未命中主要是 45/68 号“全局指针仍可达”流变体（LSan 默认把全局根视为 reachable，不报 leak），以及 12 号随机分支触发 `bad-free`。
- 40 个 case，ASan+Valgrind，4 workers：
  - 19 TP / 0 FP / 20 TN / 0 FN / 1 inconclusive
  - 两检测器结论一致。

### 7.3 正式全量运行

- 运行目录：`runs/cwe401_juliet_v1_3_asan_valgrind/`
- 输入：`juliet/raw/testcases/CWE401_Memory_Leak`（全量 CWE-401 根用例；w32 排除，wchar_t 保留）
- 规模：3316 个 case（1658 bad / 1658 good），8 workers，ASan + Valgrind 双检测器
- 耗时：990.9s（约 16.5 分钟）
- 退出状态：没有编译失败、没有超时、没有 detector 不可用；仅 1 个 `inconclusive`
- 结果文件：`results.jsonl`（3316 行）、`metrics.json`、`metrics.md`、`manifest.json`
- 独立复核：3316 个唯一 `case_id`，标签 1658/1658，混淆矩阵与 `metrics.json` 一致；`cases.jsonl`、`results.jsonl`、`metrics.json` 的 SHA-256 与 `manifest.json` 记录一致；`results.partial.jsonl` 已删除
- 注意：这是基于当前已解压 Juliet 原始目录的正式全量运行，不是等待“统一冻结 manifest”后的子集；`results.jsonl` 保留了 `metadata.juliet_relpath` 与 `variant`，可按后续统一 manifest 重新连接/筛选


## 8. 限制

1. **只观测执行到的路径**：动态分析无法触发未执行分支。例如 Juliet 的 `malloc_realloc` bad 路径只有在 `realloc` 失败时才泄漏；默认运行不会制造分配失败，因此会记为 FN，而不是伪造阳性。
2. **全局可达内存不算泄漏**：LSan/Valgrind 默认把全局变量指向的块视为 still reachable；Juliet 的 45/68 流变体属于这种情况，工具会漏报。这是工具语义，不是 harness 错误。
3. **随机分支**：约 256 个 Juliet 文件通过 `srand(time(NULL))` + `rand()%2` 选择 good/bad 分支，单次运行不可完全复现；某些 bad 变体可能随机走到 `bad-free` 而不是泄漏。结果是一次真实运行的样本，`metrics` 中会体现 `inconclusive`。
4. **ASan 与 Valgrind 的泄漏定义不同**：LSan 的 direct/indirect、Valgrind 的 definite/possible/still-reachable 不能逐条对齐；合并采用“任一报泄漏即 leak”。
5. **Valgrind 默认未安装**：正式产物记录了本地解包路径；换机器复现需安装 Valgrind 或按 1.2 解包。没有 Valgrind 时 `detectors.valgrind.status=unavailable`，不会被当成 clean。
6. **w32/wchar**：w32 排除；wchar_t 默认保留，若要贴合 Juliet 官方 Makefile 的过滤规则可加 `--exclude-wchar`（结果会不同，需在新 run 中记录）。
7. **没有故障注入**：没有使用 `failmalloc`、`ulimit` 等制造分配失败；因此“资源耗尽型”泄漏不在覆盖范围内。
8. **动态执行不等于静态证明**：`clean` 只表示当前执行配置下未观测到泄漏。

## 9. 目录结构

```text
traditional/dynamic/
├── README.md
├── run_dynamic_eval.py       # CLI 入口
└── dynleak/
    ├── cli.py                # 子命令：run / discover / check-tools / selftest
    ├── discover.py           # Juliet 发现、多文件分组、manifest
    ├── build.py              # 编译与编译失败分类
    ├── execute.py            # ASan/Valgrind 执行、超时、证据收集
    ├── sanitizer.py          # LSan/ASan 文本解析
    ├── valgrind.py           # Valgrind XML 解析
    ├── classify.py           # detector/case 判定与 failure_class
    ├── metrics.py            # 混淆矩阵、Wilson CI、分层与 Markdown
    ├── pipeline.py           # 并发编排、run 目录、manifest
    ├── toolchain.py          # 编译器/ASan/Valgrind 真实 smoke check
    ├── selftest.py           # 临时真实程序自测
    ├── config.py             # 运行参数与 Valgrind 命令
    └── util.py               # 进程组/超时/哈希/JSONL
```

## 10. 正式结果

### 10.1 运行配置

```text
run_id:  cwe401_juliet_v1_3_asan_valgrind
run_dir: traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind/
date:    2026-11-11T18:13:31Z (UTC)
cases:   3316 (1658 bad / 1658 good)
jobs:    8
tools:   gcc/g++ 15.3.0, Valgrind 3.27.1 (本地 /tmp 解包), ASan/LSan
mode:    ASan + Valgrind；单 case 10s；Valgrind timeout ×3
```

### 10.2 总体结果

| 指标 | 值 |
|---|---:|
| cases | 3316 |
| decisive | 3315 |
| TP | 1467 |
| FP | 0 |
| TN | 1658 |
| FN | 190 |
| precision | 1.0000 |
| recall | 0.8853 |
| FPR | 0.0000 |
| specificity | 1.0000 |
| F1 | 0.9392 |
| accuracy | 0.9427 |
| recall 95% Wilson CI | [0.8691, 0.8998] |
| FPR 95% Wilson CI | [0.0000, 0.0023] |
| inconclusive | 1 |

合并规则是“任一检测器报 leak 即 leak”。因此合并结果比单检测器多抓到少量交叉漏报；同时没有引入 FP。

### 10.3 单检测器

| detector | decisive | TP | FP | TN | FN | recall | FPR | F1 | 其他状态 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| ASan/LSan | 3310 | 1442 | 0 | 1658 | 210 | 0.8729 | 0.0000 | 0.9321 | 6 inconclusive |
| Valgrind | 3305 | 1459 | 0 | 1658 | 188 | 0.8859 | 0.0000 | 0.9395 | 11 inconclusive |

两个检测器的逐 case 组合：1840 个 both clean、1434 个 both leak、22 个 ASan clean/Valgrind leak、4 个 ASan leak/Valgrind clean；其余为至少一侧 inconclusive。Valgrind 单器召回略高，合并后 TP 再增加到 1467。

### 10.4 分层

| 语言 | cases | TP | FP | TN | FN | recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| C | 1736 | 712 | 0 | 868 | 156 | 0.8203 | 0.0000 |
| C++ | 1580 | 755 | 0 | 790 | 34 | 0.9569 | 0.0000 |

C 的召回明显低于 C++，主要因为 `malloc_realloc_*` 资源耗尽型用例集中在 C 侧；C++ 侧主要是 `new*` 流变体。

### 10.5 190 个 FN 的归因（全部可解释）

| 类别 | FN 数 | 原因 |
|---|---:|---|
| `malloc_realloc_*`（6 个 feature × 18） | 108 | bad 路径只有在 `realloc` 失败时才泄漏；默认运行 realloc 成功，动态检测器观测不到泄漏，也没有做故障注入 |
| Juliet 流变体 45/68 | 68 | 指针写入全局变量，LSan/Valgrind 默认把全局根视为 still reachable；工具不把 still-reachable 计为 definite leak |
| Juliet 流变体 12 | 14 | `globalReturnsTrueOrFalse()` 随机选择分支；本次运行走到 `bad-free` 或非泄漏路径，未触发泄漏 |
| 合计 | 190 | — |

唯一的 `inconclusive` 是 C++ `new_struct_twoIntsStruct_12` 的 bad 变体：ASan 报 `bad-free`，没有形成可解析的泄漏证据；`failure_class=runtime.asan_error:bad-free`。这不是被当成 clean，也没有从标签反推。

### 10.6 产物哈希

`manifest.json` 记录的 SHA-256（已独立复核）：

- `cases.jsonl`: `cc8db43b84f5eb106461cea6d86ac2b9934173c7ea5fe4abfb36690af1a7bc42`
- `results.jsonl`: `405381672467c146ac9e183f427be27fbff677be26844b6782d28a0f02218f64`
- `metrics.json`: `2983fd804329ce86bbdb43a9335a0562b1c2b808b73dd0d8de245c0cb98ac038`

### 10.7 如何解读

- **高 precision、零 FP**：1658 个 good 变体全部被判 clean，说明 harness 没有把正常程序系统性误报为泄漏。
- **recall 0.8853 不是“检测器差”这么简单**：190 个 FN 全部有明确机制，其中 108 个是“需要制造分配失败才会泄漏”，68 个是“全局仍可达”，14 个是随机分支。换成静态分析或故障注入会得到不同数字，不能直接横向比较。
- **动态结果依赖执行配置**：这是单次真实运行的样本，不应被表述为 CWE-401 的绝对检出率。

