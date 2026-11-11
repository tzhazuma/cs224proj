# SecVulEval 开发/测试划分（`secvul-split-v1`）

本目录是整个项目**唯一**的划分来源，拥有者为“划分/冻结”工作流。这里的文件在冻结后只读；运行器（`runner/`）、基线（`baseline/`）和报告（`report/`）都只消费这里的 JSON，不重新抽样、不改写。

> 与协议的一处路径差异：`research/evaluation_protocol.md` §4.7 写的是 `research/splits/split_v1.json`，但 `research/` 由另一个工作流独占并已冻结，因此本实现把同一份内容放在项目根目录的 `splits/`。`split_id`、字段结构和校验规则不变，运行器通过 `--dataset-file` 直接引用这里的文件。

## 1. 文件清单

| 文件 | 用途 | 行数/样本数 |
| --- | --- | --- |
| `split_v1.json` | 冻结清单：seed、源 SHA-256、每个 split 的 idx/pair_id、项目集合、CWE 家族与长度分布、示例来源、产物哈希 | 200 条检测记录 + 200 对配对记录 |
| `test_detection_160.json` | 检测测试集，`--dataset independent --dataset-file` | 160（128 V / 32 NV） |
| `test_pairs_180.json` | 配对测试集，`--dataset pairs --dataset-file` | 180 对 / 360 函数 |
| `dev_detection_40.json` | 检测开发集（direct/context 试点；few-shot 见 §6） | 40（32 V / 8 NV） |
| `dev_pairs_20.json` | 配对开发集（direct/context 试点） | 20 对 |
| `pilot_detection_36.json` | 开发集去掉 4 条检测示例后的 few-shot 试点子集 | 36（30 V / 6 NV） |
| `pilot_pairs_18.json` | 开发集去掉 2 对修复示例后的 few-shot 试点子集 | 18 对 |
| `dev_examples_fewshot.json` | 从开发集整理的 few-shot 示例，格式与 `runner/secvul_runner/dev_examples.json` 一致 | 4 检测 + 2 修复 |
| `example_notes.json` | 示例的人工选择理由与 rationale/explanation；清单哈希覆盖此文件 | 6 条 |
| `make_splits.py` | 生成、冻结、校验脚本；只依赖 Python 标准库 | — |
| `FREEZE.txt` | 冻结记录：源文件、示例文件、全部产物的 SHA-256 | — |

两个测试文件均保留源记录的**全部 16 个字段**，只做行过滤，不做字段改写。`metadata` 复制源文件的溯源信息，改写 `sample_count` / `vulnerable_count` / `non_vulnerable_count`（检测）或 `pair_count` / `function_count`（配对），并新增 `metadata.split` 块（`split_id`、`role`、`task`、`seed`、源文件及 SHA-256）。`samples` / `pairs` 的顺序与源文件一致，便于逐条比对。

## 2. 拆分算法

输入与种子：

- `datasets/independent_200.json`（SHA-256 `055eccc2…61dc3d`，200 条样本）
- `datasets/vulnerable_fixed_200_pairs.json`（SHA-256 `7028b98d…7214d5`，200 对）
- `seed = 42`（两个源数据集构建时使用的种子；本脚本不再做随机抽样，选择过程完全由固定规则和 SHA-256 决定）

### 2.1 检测集（40 dev / 160 test）

1. 按 `project` 分组。`independent_200` 有 80 个项目：60 个单例项目（46 V + 14 NV）、20 个多例项目（140 条，114 V + 26 NV）。
2. 只有单例项目可以进入开发集；多例项目整体留在测试集。开发集从 60 个单例项目中选 40 条（32 V + 8 NV），因此开发集每个项目恰好 1 条，测试集为其余 160 条（20 个未选单例 + 20 个多例）。
3. CWE 家族取 `cwe_list` 中第一个数字 CWE，按协议 §4.5 映射；`CWE-190` 同时出现在 `memory_buffer` 与 `integer` 两行，按表顺序归入 `memory_buffer`；非数字标记和未知 CWE 归入 `other`。
4. 长度档按全部 200 条函数正文字符数计算：`statistics.quantiles(lengths, n=4, method="inclusive")`，切点 `[561.75, 1345.5, 3113.5]`，分档规则为 `<=q1, <=q2, <=q3, >q3`。
5. V 的选择：先在候选池中每个存在的家族各选 1 条（按“该家族该长度档已选数 → 全局该档已选数 → hash”排序），再逐条补足到 32：每次选择“家族×长度档已选数最小 → 全局长度档已选数最小 → 家族已选数最小 → hash”的候选。NV 的选择：先在每个存在的长度档各选 1 条，再按“长度档已选数 → hash”补足到 8。
6. 由于候选池只有 6 个家族（`other, memory_buffer, input_validation, lifetime, null_pointer, resource`），开发集覆盖全部 6 个；候选池中没有 `integer`/`race` 单例样本，因此开发集不含这两类。测试集包含全部 7 个家族。

### 2.2 配对集（20 dev / 180 test）

1. 按 `vulnerable.project` 分组。`vulnerable_fixed_200_pairs` 有 80 个项目：63 个单例、17 个多例（137 对）。
2. 只有单例项目可以进入开发集；多例项目整体留在测试集。开发集 20 对，测试集 180 对（43 个未选单例 + 17 个多例）。
3. 家族的 CWE 取**漏洞版本**的第一个数字 CWE；长度取 `max(len(vulnerable.func_body), len(fixed.func_body))`，切点 `[635.25, 1325.5, 2441.75]`。
4. 选择规则同检测集：先每个家族 1 条，再按“家族×长度档已选数 → 全局长度档已选数 → 家族已选数 → `sha256('split:' + pair_id)`”补足到 20。开发集覆盖池中全部 6 个家族，长度档为 5/5/5/5。
5. 一对的 `vulnerable` 与 `fixed` 始终进入同一个 split；脚本按 `pair_id` 整体移动并逐对校验。

### 2.3 项目隔离的范围

每个任务内部严格满足：同一项目不会同时出现在该任务的 dev 与 test；多例项目整体留在 test。两个任务之间**不**强制同一项目同侧——这是协议 §4.2 的设计（两任务各自独立拆分）。

本数据上跨任务全局互斥不可行：检测 dev 的 40 个项目中有 2 个在配对 test，配对 dev 的 20 个项目中有 5 个在检测 test；若要求“同一项目在两个任务中同侧”，这些项目必须整体迁移，无法同时满足检测 160 条 / 配对 180 对的固定配额（例如 `FFmpeg` 在检测集中是单例、在配对集中是多例，只能整体留在 test）。脚本因此记录而不是隐藏这些交集：

- 检测 dev ∩ 配对 test：`yara, znc`（2 个）
- 配对 dev ∩ 检测 test：`Fast-DDS, OpenSC, file, htmldoc, libgd`（5 个）

同一项目的**源 idx 和函数正文**在 dev/test 之间仍然完全不重叠（见 §5 校验），跨任务共享只涉及项目名/代码风格，不涉及测试样本本身。报告引用时应把这一点写成已知限制，而不是声称“全局项目互斥”。

## 3. 统计结果

检测集：

| split | 样本 | V | NV | 项目数 | 家族分布 | 长度档 |
| --- | --- | --- | --- | --- | --- | --- |
| dev | 40 | 32 | 8 | 40（全部单例） | other 18, memory_buffer 14, input_validation 3, lifetime 3, null_pointer 1, resource 1 | 10/9/10/11 |
| test | 160 | 128 | 32 | 40（20 单例 + 20 多例） | other 57, memory_buffer 46, lifetime 23, input_validation 14, null_pointer 14, race 4, integer 2 | 40/41/40/39 |

配对集：

| split | 对数 | 项目数 | 家族分布 | 长度档 |
| --- | --- | --- | --- | --- |
| dev | 20 | 20（全部单例） | memory_buffer 4, null_pointer 4, input_validation 4, other 5, lifetime 2, resource 1 | 5/5/5/5 |
| test | 180 | 60（43 单例 + 17 多例） | memory_buffer 64, other 58, input_validation 20, lifetime 12, null_pointer 12, race 7, integer 4, resource 3 | 45/45/45/45 |

开发集项目（检测，40 个）：
`Espruino, LibRaw, WavPack, asterisk, bluez, clickhouse-driver, cockpit, dcmtk, drachtio-server, envoy, esp, exim, fdupes, fribidi, haproxy, hermes, iperf, isolated-vm, kamailio, libevent, libfep, libjpeg-turbo, libminizinc, libxsmm, md4c, memcached, mruby, nspluginwrapper, opensips, orjson, qemu, qpdf, serenity, shadow, smartdns, stunnel, suricata, wireshark, yara, znc`

开发集项目（配对，20 个）：
`CycloneTCP, Fast-DDS, OpenSC, Phoenixcoin, aspell, diplib, file, flatpak, htmldoc, illumos-gate, kvm-guest-drivers-windows, lftp, libgd, memcached, njs, picotcp, samurai, sudo, wireshark, xreader`

全部 test 项目集合、每个样本的 idx、每个 pair 的 `pair_id`、家族/长度档和源码 SHA-256 都在 `split_v1.json` 中，不依赖本 README 的摘录。

> 注意：检测 dev 的 40 个项目与配对 dev 的 20 个项目合并去重后是 58 个（`memcached`、`wireshark` 同时出现在两侧开发集），不是 60。这里的“项目数”始终按任务分别统计。

## 4. 与协议 §4 的对应关系

| 协议要求 | 本实现 |
| --- | --- |
| 固定种子 42 | `seed: 42`，写入清单与每个数据文件的 `metadata.split` |
| 检测 40 dev（32V/8NV）+ 160 test（128V/32NV） | 是，脚本硬性断言 |
| 配对 20 dev + 180 test，pair 不拆开 | 是，按 `pair_id` 整体移动并逐对校验 |
| 项目级互斥 | 每个任务内部是；跨任务按协议 §4.2 独立拆分并显式记录交集 |
| 家族/长度分层 | 开发集覆盖候选池中全部家族；长度档尽量均衡 |
| 记录 idx、pair_id、项目集合、分布 | `split_v1.json` 的 `detection.*.records`、`pairs.*.records`、`*.projects`、`*.cwe_family_counts`、`*.length_quartile_counts` |
| 记录源 SHA-256 | `source_files`（两个数据集 + 示例说明文件 + 生成脚本） |
| 测试冻结 | `FREEZE.txt` 记录全部产物哈希；`build`/`freeze` 默认拒绝覆盖已有冻结 |
| 失败时不得静默放宽 | 所有配额/隔离/分区/标签检查失败即 `SplitError`，退出码 2 |

未纳入本目录的内容：协议 §4.4 中 B2 的 30 对修复子集。它是在 180 对测试集上的**二次分层抽样**，属于修复评估工作流；本目录只固定 180 对测试集，避免在这里提前消费测试集。若需要，应由报告/基线工作流按协议单独抽样并记录其抽样框。

## 5. 校验与冻结

`make_splits.py` 在写出任何文件之前运行以下断言（任一失败即报错退出，不会留下“部分拆分”）：

- 检测 40 = 32V + 8NV，测试 160 = 128V + 32NV；配对 20/180；
- 检测、配对各自是源数据的**分区**：每个源 idx / pair_id 恰好出现一次；
- 检测 dev/test 项目交集为空；配对 dev/test 项目交集为空；
- 跨任务源 idx 交集为空（两个源数据集本身不共享 idx）；
- dev 与 test 之间没有完全相同的函数正文（SHA-256 集合交集为空）；
- 每对的两侧项目相同、idx 不同、标签分别为 `true`/`false`；
- 每条派生记录与源记录**深度相等**（逐字段比对，确保只做行过滤）；
- 示例的 `idx` / `pair_id` 必须来自 dev；检测示例顺序为 V,NV,V,NV，两个 V 家族不同，两个 NV 长度档不同；修复示例分别来自 `memory_buffer` 与 `input_validation`；
- 示例文本不得包含 `CVE-`、`CWE-`、`NVD-CWE`、`fixed_func_idx`、`changed_lines`、`changed_statements`、`commit_id`、`commit message` 等标记。

此外，`build` / `freeze` / `verify` 都会用运行器自己的加载器在临时目录中重新加载产物（不是复制一份校验逻辑）：

- `secvul_runner.datasets.load_dataset(..., "independent" | "pairs")`：数量、标签、`fixed_func_idx` 指向、pair 一致性；
- `secvul_runner.prompts.load_dev_examples(...)`：对**两个测试文件**分别执行示例隔离检查；
- `build_prompt(..., "few-shot")`：实际构造一次检测和一次修复的 few-shot 消息，确认 10/6 条消息、示例 ID 和哈希正确。

实际执行结果（WSL，Python 3.14.8）：

```text
$ python3 splits/make_splits.py verify
split verification
  artifacts: 8
  detection: dev=40 test=160; projects dev=40 test=40 intersection=0
  pairs: dev=20 test=180; projects dev=20 test=60 intersection=0
  cross-task project overlap (allowed, recorded): det-dev/pair-test=2, pair-dev/det-test=5
  source idx: dev=80 test=520 overlap=0
  shared function bodies dev/test: 0
  runner: test_detection=160 units, test_pairs=180 units

OK: artifacts match a fresh build and the freeze record
```

运行器 CLI 的 dry-run（不联网、不产生结果）也全部通过：

| 命令目标 | 结果 |
| --- | --- |
| 检测 test + few-shot + detection | 160 个请求 |
| 配对 test + few-shot + repair | 180 个请求 |
| 配对 test + few-shot + both | 540 个请求（360 检测 + 180 修复） |
| 检测 test + context + detection | 160 个请求（上下文清洗路径） |
| `pilot_detection_36.json` + few-shot | 36 个请求 |
| `pilot_pairs_18.json` + few-shot + both | 54 个请求 |
| `dev_detection_40.json` + few-shot | 按设计被拒绝：示例 `det-dev-9493` 的 `source_idx` 在评估集中 |

最后一行不是缺陷，而是运行器的隔离规则：使用本目录的 dev 派生示例时，评估文件不能同时包含示例来源样本。需要 few-shot 试跑时请用 `pilot_detection_36.json` / `pilot_pairs_18.json`，或使用运行器自带的合成示例文件。**没有任何真实 API 调用**，也没有生成任何指标或结果；DeepSeek 调用问题（401）与本目录无关。

## 6. Few-shot 示例

`dev_examples_fewshot.json` 的 6 条示例全部来自开发集，顺序和内容在冻结后不可替换：

| 角色 | 来源 | 家族/长度档 | 选择理由 |
| --- | --- | --- | --- |
| 检测 V | `idx=9493`（libevent `search_make_new`） | memory_buffer / q2 | `base_name[base_len - 1]` 在空串时下标下溢，单行可指认的越界读 |
| 检测 NV | `idx=17182`（isolated-vm `GetKey`） | other / q1 | 只做 V8 句柄检查与转换，无裸指针、定长写入或未检查索引 |
| 检测 V | `idx=11371`（mruby `mrb_io_initialize_copy`） | lifetime / q2 | 先释放目标 `mrb_io` 再取源指针，自拷贝时 `fptr_orig` 指向已释放内存 |
| 检测 NV | `idx=6620`（nspluginwrapper `string_of_NPPVariable`） | other / q2 | 纯 switch 到静态字符串，无分配、无缓冲区写入 |
| 修复 | `pair_id=19988:19989`（OpenSC `enum_dir`） | memory_buffer / q2 | 把栈上 `files` 数组从标准 APDU 大小改为扩展 APDU 大小 |
| 修复 | `pair_id=7686:7683`（file `dophn_exec`） | input_validation / q3 | 把 `pread(...) == -1` 改为要求读满 `xph_sizeof`，避免短读留下未初始化的程序头 |

为什么是“人工挑选”而不是按 hash 自动取前几条：协议 §4.6 只要求示例固定、来自开发集、不按测试表现挑选，并给出家族/长度档约束；“同分按 hash”需要一个前置评分。自动 hash 顺序在本数据上抽到的首条检测 V（`fdupes`）修复仅涉及 `remove()` 错误分支，难以写出与标签一致的 rationale；为避免把噪声标签当成教学信号，这里改为在**开发集内**按“缺陷可指认/无危险操作 + 家族/档位约束”挑选，并把选择理由、prose 和哈希一并冻结。该选择只看开发集代码，不看任何测试结果。示例 rationale/explanation 是人工撰写的，不含 CVE/CWE/commit/idx/改动行等元数据。

运行器加载示例时会对**评估文件中的全部函数**做隔离检查，并禁止示例声明的 `source_idx` 出现在评估集。因此：

- 用 `test_detection_160.json` / `test_pairs_180.json` 时，示例与测试集不相交，检查通过；
- 用 `dev_detection_40.json` / `dev_pairs_20.json` 时，示例来源本身就在评估集中，运行器会拒绝（符合其设计）；
- `pilot_*` 是从 dev 中减去示例来源后的派生子集，专门用于 few-shot 冒烟。

协议 §4.6 还给 B1 规定了 2 对 A/B verdict 示例；运行器的示例 schema 只有 `detection` 和 `repair` 两类、没有 B1 任务，因此本文件不生成 B1 示例。B1 若由独立脚本实现，应从同一 dev 划分另取 2 对并单独冻结。

## 7. 在 WSL 中运行

以下命令都在项目根目录执行；`--out-dir` 放在 `runner/runs/` 下（真实运行时由运行器管理，本目录不写运行产物）。

```bash
# 检测测试集（few-shot）
cd runner && python3 -m secvul_runner \
  --dataset independent --dataset-file ../splits/test_detection_160.json \
  --strategy few-shot --task detection \
  --dev-examples ../splits/dev_examples_fewshot.json \
  --model "$SECVUL_MODEL" --out-dir ../runner/runs/split_v1_det_fewshot

# 配对测试集（修复）
cd runner && python3 -m secvul_runner \
  --dataset pairs --dataset-file ../splits/test_pairs_180.json \
  --strategy few-shot --task repair \
  --dev-examples ../splits/dev_examples_fewshot.json \
  --model "$SECVUL_MODEL" --out-dir ../runner/runs/split_v1_pair_repair

# 先验证请求、不联网
cd runner && python3 -m secvul_runner ... --dry-run --out-dir /tmp/split_v1_dryrun
```

真实运行需要 `DEEPSEEK_API_KEY`（或 `--api-key-env` 指定的变量）；密钥只从环境变量读取。运行器会把数据文件 SHA-256、示例文件 SHA-256、prompt 版本和配置指纹写入 `manifest.json`，可与 `FREEZE.txt` 对照。

### 复现与重新冻结

```bash
python3 splits/make_splits.py preview   # 只打印选择，不写文件
python3 splits/make_splits.py build     # 重新生成全部产物（需 example_notes.json）
python3 splits/make_splits.py freeze    # 校验产物后写 FREEZE.txt
python3 splits/make_splits.py verify    # 与磁盘/冻结记录逐字节比对
```

- 生成过程没有时间戳、随机数或环境依赖；相同源文件 + 相同 `example_notes.json` + 相同 `make_splits.py` 会得到**逐字节相同**的 8 个产物（`FREEZE.txt` 是唯一带 `generated_utc` 的文件）。
- `build` / `freeze` 在 `FREEZE.txt` 已存在时默认拒绝覆盖；`--force` 仅用于明确要替换同一 `split_id` 的错误冻结。正式修改划分必须同时改 `SPLIT_ID`（如 `secvul-split-v2`）并重新走 build → freeze，不能只改 JSON。
- 当前冻结哈希见 `FREEZE.txt`；`split_v1.json` 的 SHA-256 为 `7b346713095c5396dda6040ea7254c7bc906c6cd7fca0e5933ebcb51372bb70b`。`FREEZE.txt` 同时记录生成脚本 `make_splits.py` 的 SHA-256；脚本改动后 `verify` 会失败，必须重新 build → freeze。

## 8. 限制与非声明

1. **开发集都是小型单例项目**。检测 dev 的 40 个项目每个只有 1 条样本，配对 dev 的 20 个项目每个只有 1 对；`linux`、`Chrome` 等多例项目全部在测试集。开发集与测试集的领域/项目规模不完全一致，few-shot 示例和 dev 试点不能代表测试集上的项目分布。这是协议 §4.2 的已知代价。
2. **跨任务项目重叠**：2 + 5 个项目分别在一个任务是 dev、在另一个任务是 test。协议只要求任务内项目互斥；本实现显式记录，不把它包装成全局隔离。两个任务的源 idx、函数正文仍然完全不重叠。
3. **标签噪声**：源数据集的标签并非全部可人工复核（例如部分 `other`/NVD-noinfo 样本的修复只涉及错误处理）。本目录只做划分，不重新标注、不声称标签正确；示例已尽量选可指认的样本，但这不改变测试集标签的原始质量。
4. **CWE 家族只是分层工具**：家族来自协议 §4.5 的粗映射，不是官方分类学；`other` 占比高（检测 test 57/160、配对 test 58/180），按家族分层不能解释为 CWE 平衡。
5. **不包含 B2 的 30 对子集**：见 §4。测试集本身固定，二次抽样应由使用方按协议执行并登记。
6. **不做模型调用**：本目录没有、也不应该产生任何模型输出、指标或“通过率”。所有验证都是加载器/请求构造层面的；真实 DeepSeek 调用因用户 OpenCode Go key 过期返回 401，未进行。
7. **运行器 UID**：协议 §5.2 的 HMAC UID/salt 方案未被运行器采用；运行器内部用 `idx`/`pair_id` 构造 `sample_id`，且不把标签或 UID 放进 prompt。本目录不额外生成 `salt.txt`，避免制造一个无人消费的“安全”文件；如需 UID，应由运行器工作流统一实现。
8. **派生文件不扩大冻结范围**：`pilot_*` 只是 dev 的便利子集，不改变 40/20 的 dev 配额，也不参与测试；`dev_*` 只用于开发/试点，不能作为论文中的测试证据。

## 9. 变更记录

- `2026-11-11`：创建 `secvul-split-v1`。冻结检测 40/160、配对 20/180；生成测试/开发/试点 JSON、6 条 dev few-shot 示例和 `FREEZE.txt`。全部校验和 runner dry-run 通过；无真实 API 调用。
