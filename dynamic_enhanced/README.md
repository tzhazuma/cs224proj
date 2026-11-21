# 动态分析增强：真实故障注入 + LSan 全局根控制（Juliet CWE-401 test 140）

本目录只做一件事：把旧 ASan/LSan 在冻结 test 集上**观测不到**的 12 个 bad 单元变成**可观测、可复核**的证据，同时证明 70 个 good 单元不会因此产生误报。

结论先行（全部来自本目录已落盘的真实运行，`runs/test140_enhanced_v3`）：

| 指标 | 值 |
| --- | ---: |
| 单元 | 140（bad 70 / good 70） |
| TP / FP / TN / FN | **70 / 0 / 70 / 0** |
| coverage | 140/140 = 1.000 |
| 旧 ASan 不可观测的 bad | 12（7 个 `malloc_realloc` + 5 个 `_68` 全局指针） |
| 由新模式给出明确证据的 bad | **12 / 12** |
| good 误报 | **0 / 70**（三个模式均为 0） |
| 编译失败 / 超时 / 其他 ASan 错误 | 0 / 0 / 0 |

新增的 12 个证据不是猜测，也不是按文件名推断：7 个来自**真实让 `realloc` 返回 NULL** 的链接期故障注入，5 个来自**关闭 LSan 全局根**后的可达性变化。每个判定都能回溯到具体的分配栈帧、源码行、注入调用序号和运行时日志。

---

## 1. 问题：旧 harness 为什么看不见这 12 个

| 子群 | bad 代码的实际行为 | 默认执行的路径 | 旧 ASan/Valgrind 结果 |
| --- | --- | --- | --- |
| `malloc_realloc_*`（7 个） | `data = realloc(data, N)` 直接覆盖指针；只有 `realloc` 失败时初始块才失去唯一引用 | `realloc` 成功，随后 `free(data)` | `clean`，因为没有失败 |
| `*_68`（5 个） | 唯一指针写入全局变量，bad sink 不 `free` | 进程退出时全局仍指向该块 | `clean`，因为 LSan 把全局当根，判为 still reachable |

旧 README（`juliet_repair/README.md` §6、`traditional/dynamic/README.md`）把这两类记为“不可观测”，并明确没有做故障注入。本目录补上这两个真实机制，而不是改标签或改判定。

---

## 2. 方法

### 2.1 单元、编译与 probe

- 单元来自 `juliet/subset_units.jsonl` 的冻结 `split=test`：140 个，70 bad / 70 good，70 组；启动时校验 `juliet/FREEZE.json` 里的 `subset_units_sha256`，不一致直接退出。
- 直接编译**原始未修改**的 Juliet 源文件；评测端只额外提供一个 probe `main()`，调用该单元自己的 `bad` 或 `good` 入口。bad 用 `-DOMITGOOD`，good 用 `-DOMITBAD`。
- 编译参数：`gcc/g++ -O0 -g -fsanitize=address -fno-omit-frame-pointer -w`，链接 `juliet/raw/testcasesupport/io.o`、`std_thread.o`、`-lpthread -lm`。和 `juliet_repair/scripts/repair_lib.py` 的编译口径一致，因此旧结果可比。

### 2.2 三种模式（同一单元、同一 probe）

| 模式 | 二进制 | 环境 | 回答的问题 |
| --- | --- | --- | --- |
| `default` | plain | `ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=23`；`LSAN_OPTIONS=exitcode=23:use_stacks=0:use_registers=0` | 复现旧 ASan 判定（不把栈/寄存器当根） |
| `realloc_fail` | wrap | 同上，另加 `DYNENH_REALLOC_FAIL_NONNULL=1` | 首次 `realloc(非 NULL)` 真实失败时，初始块是否泄漏 |
| `nogobal` | plain | `LSAN_OPTIONS=...:use_globals=0` | 去掉全局根后，全局持有的块是否变成不可达 |

`realloc_fail` 的实现是链接期 `-Wl,--wrap=realloc`（`dyne/assets/inject_realloc.c`）：

- 每次调用都向 fd 2 写一行 `[dynenh] realloc #N` 和 `ptr=NULL/nonnull`，日志本身不调用 malloc；
- 只让**第一个收到非 NULL 指针**的 `realloc` 返回 NULL，其余调用转给 `__real_realloc`（ASan 构建里就是 ASan 的拦截器，分配器账本保持一致）；
- `realloc(NULL, N)` 故意放行：让 `char_realloc_*` 这类“首次分配”保持原语义，而不是提前 `exit(-1)` 把泄漏掩盖掉；
- 因此 `injected` 是运行事实，不是配置假设：14 个单元在运行中真正触发了注入（7 个 bad + 7 个配对 good），其余 126 个没有执行到非 NULL `realloc`，该模式记为 `applicable=false`。

### 2.3 归因规则（防止“运行时噪声”变成误报）

`nogobal` 会让 glibc 的 stdout/wchar 缓冲区（1,024 / 4,096 / 16,384 字节）和 libstdc++ 的进程级分配变成 LSan 报告。**它们在 70 个 good 单元里同样出现**，如果直接把“有泄漏”当预测，会产生 70 个误报。

因此每条泄漏块都做归因：

1. 解析 LSan 的每个 `Direct/Indirect leak of N byte(s)` 块及其分配栈；
2. 跳过工具链/运行时帧（`/usr/`、`/lib`、`libsanitizer`、`<...>`）、评测端 probe 帧和 `__wrap_realloc` 帧；
3. 取**第一个带源码位置的帧**作为分配点；只有该文件属于本单元自己的源文件（或同组头文件）时，才把这块算作本单元的泄漏。

这条规则只看**运行时的分配栈**，不读文件名、不读标签、不按组名预测。`nogobal` 的 70 个 good 单元原始泄漏计数是 70，归因后全部为 0；这就是过滤器按预期工作的直接证据。

### 2.4 判定

- `leak`：任一**适用**模式出现至少一个归因泄漏；
- `clean`：所有适用模式都没有归因泄漏；
- `not_evaluable`：编译/运行失败，不写成负例（本次 0 个）；
- 每个模式、每个单元都记录：编译命令/返回码/耗时/stderr、运行返回码/墙钟/超时、原始与归因泄漏块、分配点函数与源码行、注入调用序号、stdout 哈希、失败分类。

---

## 3. 结果

完整汇总（混淆矩阵、逐模式计数、12 单元表、旧结果对比、运行时间）在
`runs/test140_enhanced_v3/metrics.md`，机器可读版本是同目录的 `metrics.json`。

### 3.1 三种模式的证据分布

| 模式 | 适用单元 | bad 归因泄漏 | good 归因泄漏 | bad 原始泄漏 | good 原始泄漏 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `default` | 140 | 58 | 0 | 58 | 0 |
| `realloc_fail` | 14 | 7 | 0 | 7 | 0 |
| `nogobal` | 140 | 63 | 0 | 70 | 70 |
| **并集** | — | **70** | **0** | — | — |

- `default`：58/70 bad，和旧 ASan 完全一致（140/140 单元判定一致）。
- `realloc_fail`：只有 14 个单元真正触发注入（7 个 `malloc_realloc_*` bad + 7 个配对 good）。7 个 bad 全部泄漏，7 个 good 全部干净——包括“失败时先 `free` 原块再退出”的正确实现。
- `nogobal`：63/70 bad。58 个是默认路径本来就泄漏的块，另外 5 个正是 `*_68` 全局指针单元。
- `nogobal` 的 70/70 good 原始泄漏全部是 glibc/libstdc++ 噪声，归因后 0；`default` 和 `realloc_fail` 的 good 原始泄漏也是 0。

### 3.2 12 个条件/可达性单元

| 单元 | 证据模式 | default | realloc_fail | 注入调用 | nogobal | 归因字节 |
| --- | --- | --- | --- | ---: | --- | ---: |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_01__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_09__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int64_t_18__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_int_01__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 400 |
| `CWE401_Memory_Leak__malloc_realloc_int_18__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 400 |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_01__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 800 |
| `CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18__bad` | `realloc_fail` | clean | **leak** | 1 | clean | 800 |
| `CWE401_Memory_Leak__new_TwoIntsClass_68__bad` | `nogobal` | clean | clean | — | **leak** | 8 |
| `CWE401_Memory_Leak__new_array_twointsStruct_68__bad` | `nogobal` | clean | clean | — | **leak** | 800 |
| `CWE401_Memory_Leak__twoIntsStruct_malloc_68__bad` | `nogobal` | clean | clean | — | **leak** | 800 |
| `CWE401_Memory_Leak__wchar_t_calloc_68__bad` | `nogobal` | clean | clean | — | **leak** | 400 |
| `CWE401_Memory_Leak__wchar_t_malloc_68__bad` | `nogobal` | clean | clean | — | **leak** | 400 |

两个具体例子（均在 `results_units.jsonl` 中逐字段可查）：

- `malloc_realloc_int_01__bad`：`realloc_fail` 的 LSan 块为 400 字节，分配点 `..._malloc_realloc_int_01.c:27`（初始 `malloc`），注入发生在第 1 次非 NULL `realloc`；同一单元的 good 版本同样注入第 1 次，但没有泄漏（错误路径先 `free(data)`）。
- `new_TwoIntsClass_68__bad`：`nogobal` 的块为 8 字节（`new TwoIntsClass`，两个 int），分配点 `..._new_TwoIntsClass_68a.cpp:41`；`default` 下同一块因全局根存在而不可见。

### 3.3 与旧 ASan / Valgrind 对比

旧运行：`traditional/dynamic/runs/cwe401_juliet_v1_3_asan_valgrind`（3,316 case，覆盖全量 CWE-401 根用例；本目录用 `(sources, defines)` 精确匹配 140/140 个 test 单元）。

| 对比 | 一致 | 说明 |
| --- | ---: | --- |
| 新 `default` vs 旧 ASan | 140/140 | 同一根集策略，复现成功 |
| 新并集 vs 旧 ASan/Valgrind 任一 | 128/140 | 差异恰好是 12 个 bad；全部由 `realloc_fail`/`nogobal` 解释 |
| good 单元判定变化 | 0 | 旧 70 good 全 clean，新 70 good 仍全 clean |

判定发生变化的只有 12 个 bad，方向和机制都与第 1 节一致；没有出现任何 good 从 clean 变成 leak。

运行时间（同一台 WSL，GCC 15.3.0）：

| 口径 | 值 |
| --- | ---: |
| 140 单元总耗时（每单元 2 次编译 + 3 次运行） | 315,596 ms |
| 每单元 mean / p50 / p95 / max | 2,254 / 2,062 / 3,746 / 4,977 ms |
| `default` 单次运行 mean / p95 | 62.6 / 135 ms |
| `realloc_fail` 单次运行 mean / p95 | 68.9 / 142 ms |
| `nogobal` 单次运行 mean / p95 | 147.9 / 180 ms |
| 旧 ASan 单次运行 mean | 74.5 ms |

失败分类（单元级）：`leak` 70，`clean` 70；没有 `compile_error`、`timeout`、`asan_error:*`、`harness_error`。模式级的 `unattributed_runtime_leak`（只有 glibc/libstdc++ 噪声）共 77 个 `nogobal` 运行，全部是 good 单元或本来就不泄漏的 bad 单元，未计入预测。

### 3.4 磁盘上的证据

`runs/test140_enhanced_v3/`：

| 路径 | 内容 |
| --- | --- |
| `manifest.json` | 冻结哈希、140 个单元的源文件哈希、环境、工具版本、模式定义、结果文件哈希 |
| `results_units.jsonl` | 140 行，每单元最终判定、证据模式、运行时间、失败分类 |
| `results_raw.jsonl` | 420 行，每单元 × 每模式的完整运行记录 |
| `cases/<unit_key>_<label>/build_plain.json` | 编译命令、返回码、耗时、stderr 尾部、probe 文本 |
| `cases/<unit_key>_<label>/build_wrap.json` | 注入构建的同一组字段 |
| `cases/<unit_key>_<label>/run_<mode>.json` | 返回码、墙钟、原始/归因泄漏块、分配栈、注入调用、stdout 哈希 |
| `cases/<unit_key>_<label>/run_<mode>/stderr.txt` | 原始 LSan/ASan 输出 |
| `metrics.json` / `metrics.md` | 汇总指标、12 单元表、旧结果对比、运行时间 |
| `verify.json` | 完整性校验（140/70/70、哈希、无 undecided、selftest PASS） |
| `hybrid/` | 供 hybrid 直接读取的统一结果（见 §5） |

---

## 4. 自检与复现

```bash
# 0) 环境：WSL Ubuntu，gcc/g++ 15.3.0；不需要网络和任何 API key
cd /mnt/c/Users/tzh03/Downloads/cs224proj/dynamic_enhanced

# 1) 合成 control：证明三种机制的方向性
python3 run_dynamic_enhanced.py selftest
# 6/6 PASS：普通泄漏、正确释放、latent realloc bad/good、全局泄漏、全局释放

# 2) 全量 140 单元 × 3 模式
python3 run_dynamic_enhanced.py run --run-id test140_enhanced_v3 --jobs 8

# 3) 指标、报告、hybrid 导出、完整性校验
python3 run_dynamic_enhanced.py report --run-dir runs/test140_enhanced_v3
python3 run_dynamic_enhanced.py export --run-dir runs/test140_enhanced_v3
python3 run_dynamic_enhanced.py verify --run-dir runs/test140_enhanced_v3
# -> {"status": "PASS", "problems": []}
```

`selftest` 的 6 个 control 和预期：

| control | default | realloc_fail | nogobal |
| --- | --- | --- | --- |
| 普通泄漏 | leak | 不适用 | leak |
| 正确释放 | clean | 不适用 | clean |
| latent realloc bad | clean | **leak** | clean |
| latent realloc good | clean | clean | clean |
| 全局泄漏 | clean | 不适用 | **leak** |
| 全局释放 | clean | 不适用 | clean |

“不适用”表示注入没有触发（程序里没有非 NULL `realloc`），该模式的判定被排除；该次运行仍可能复现普通路径的泄漏，例如“普通泄漏”control 在 wrap 构建里也会报 leak，但那不是注入带来的证据。

任何一次重跑都必须使用新的 `--run-id`；`run` 拒绝写入已存在的目录，不会覆盖旧结果。

---

## 5. 供 hybrid 使用

`dynamic_enhanced/exports/hybrid/`（以及每次 run 内的 `hybrid/`）包含：

- `cases.jsonl`：140 行，`case_id`、`cwe`、`language`、`sources`、`defines`、`label_source`；键与 `juliet/subset_units.jsonl` 一致。
- `results.jsonl`：140 行，`case_id`、`outcome`（`leak`/`clean`/`inconclusive`）、`failure_class`（只在真实 harness 异常时非空）、`detectors.asan.status/evidence`、`detectors.valgrind.status`、逐模式摘要、`evidence_text`。
- `manifest.json`：源 run、行数、SHA-256、loader 契约。

兼容性已实测：把 `hybrid/build_inputs.py` 的 `DYNAMIC_RUN` 指向该目录后，`load_dynamic()` 返回 140/140 个键、0 个缺失，`render_dynamic()` 对 140 条记录全部可渲染。

```python
# hybrid/build_inputs.py 的唯一改动（不在本目录执行）
DYNAMIC_RUN = ROOT / "dynamic_enhanced/exports/hybrid"
```

注意事项：

- 本目录**不重跑 Valgrind**（当前 WSL 没有 valgrind，旧 run 的本地产物也已不在）。因此导出里的 `detectors.valgrind.status` 显式为 `unavailable`，`render_dynamic` 会如实写成“not available … NOT a clean result”；旧 Valgrind 的对比只出现在 `metrics.json` 的 `old_comparison`，没有被冒充成新证据。
- 12 个单元在导出里是 `outcome=leak`，`evidence.primary_mode` 标明是 `realloc_fail` 还是 `nogobal`；`evidence_text` 逐模式写出“注入调用序号/归因字节/分配点”，便于 hybrid 的证据提示直接引用。
- 导出里没有标签字段；`label` 只在 `results_units.jsonl` 的评测侧用于算指标。

---

## 6. 限制与不能声称的事

1. **仍然是单路径观测。** 每个模式只执行 probe 调用的一次运行；没有 fuzzing、覆盖率引导或输入生成。`realloc_fail` 只让**第一次非 NULL** `realloc` 失败；如果某个单元只在第二次失败时泄漏，本实验不会覆盖（本 test 集的 7 个单元都只有一次非 NULL `realloc`）。
2. **`nogobal` 是全局根的总开关，不是逐变量根映射。** 它证明“去掉全局根后该块不可达”，不能指出是哪一个全局变量持有它；本数据集的 5 个 `_68` bad 单元只有一个全局指针，配对 good 单元在同样设置下干净。没有使用 `__lsan_register_root_region` 之类的逐根实验。
3. **`nogobal` 的原始泄漏数不能当误报数。** glibc/libstdc++ 的进程级分配在 70 个 good 单元里都会出现；本目录用分配栈归因排除它们，并同时保留原始计数（70/70）供审计。归因规则依赖调试信息（`-g -O0`），换优化级别或 strip 后需要重新验证。
4. **Valgrind 没有重跑。** 当前 WSL 未安装 valgrind，旧 run 使用的 `/tmp/valgrind-root` 也已不存在；对比对象是归档结果。Valgrind 没有等价的“关闭全局根”开关，所以 5 个 `_68` 单元无法用 Memcheck 复核——这是工具语义限制，不是遗漏。
5. **`clean` 不是“无泄漏证明”。** 三个模式都 clean 只说明这些执行路径上没有归因泄漏；good 单元如果存在未执行路径上的泄漏，本实验看不到。反过来，12 个 bad 的新证据是“在该失败/根集条件下真实观测到泄漏”，不是“任意条件下都会泄漏”。
6. **运行时间不可跨机器比较。** 62.6 ms 的 `default` 均值是 GCC 15.3.0 + 本机 WSL 的结果；旧 ASan 的 74.5 ms 来自旧 run 的 `execution.duration_ms`，只作同机粗略对照。
7. **不能写“动态检测 100%”。** 正确说法是：在冻结 test 140 上，`default + realloc_fail + nogobal` 的并集对 70 bad / 70 good 达到 70/70 与 0 FP，且 12 个旧不可观测单元全部有可复核证据。这不是对所有 CWE-401 变体、所有编译器或所有分配器行为的保证。
8. **不能把本目录的 good 0 FP 外推到其他 split。** dev 60 没有跑；所有数字仅限 `split=test` 的 140 个冻结单元。

---

## 7. 目录

```text
dynamic_enhanced/
├── README.md
├── run_dynamic_enhanced.py          # CLI: selftest / run / report / export / verify
├── dyne/
│   ├── config.py                    # 路径、模式、环境变量、超时
│   ├── units.py                     # 冻结 test 140、哈希校验
│   ├── probe.py                     # 入口发现与 probe main
│   ├── build.py                     # plain / wrap 两种编译
│   ├── assets/inject_realloc.c      # --wrap=realloc 故障注入
│   ├── execute.py                   # pty 运行、环境、墙钟
│   ├── parse.py                     # LSan 块解析、归因、失败分类
│   ├── pipeline.py                  # 140 × 3 调度与逐单元证据
│   ├── metrics.py                   # 混淆矩阵、旧结果对比、运行时间
│   ├── report.py                    # metrics.md
│   ├── export.py                    # hybrid 兼容 cases/results
│   └── selftest.py                  # 6 个合成 control
├── selftest/selftest.json           # 6/6 PASS
├── exports/hybrid/                  # 稳定导出（指向最近一次正式 run）
└── runs/test140_enhanced_v3/        # 正式结果与逐单元证据
```

所有 Python、编译和运行都在 WSL Ubuntu 内完成；本目录不读取、不打印、不保存任何 API key，也没有发起任何网络请求。
