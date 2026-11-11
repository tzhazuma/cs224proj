# SecVulEval 定性案例（中间导出）

> **中间导出，不是正式结果。** 本文件只使用所选策略/数据集的已完成运行；缺失或跳过的类别见下方。正式结论以 `cases.json` / `cases.md` 为准。

- 生成时间（UTC）：`2026-11-11T12:13:11.423202+00:00`
- 脚本版本：`qualitative-v1`
- 模式：`intermediate`；formal=`False`
- 实际使用策略/数据集：`independent=direct；pairs=direct`
- 案例数：7
- 六个运行全部完成：`True`
- 选择规则版本：`qualitative-v1`

**输入运行**

| 策略 | 数据集 | 状态 | 记录/期望 | 完成时间 | run_id |
| --- | --- | --- | ---: | --- | --- |
| direct | independent | complete | 288/288 | 2026-11-11T11:24:17.570+00:00 | `test_v1_direct_independent` |
| direct | pairs | complete | 540/540 | 2026-11-11T11:34:25.227+00:00 | `test_v1_direct_pairs` |
| few-shot | independent | complete | 288/288 | 2026-11-11T11:39:44.635+00:00 | `test_v1_few-shot_independent` |
| few-shot | pairs | complete | 540/540 | 2026-11-11T11:48:57.230+00:00 | `test_v1_few-shot_pairs` |
| context | independent | complete | 288/288 | 2026-11-11T11:54:41.433+00:00 | `test_v1_context_independent` |
| context | pairs | complete | 540/540 | 2026-11-11T12:05:01.678+00:00 | `test_v1_context_pairs` |

**警告**

- test_v1_direct_independent: 19 schema-invalid records; these are real model outputs, not missing data
- test_v1_direct_pairs: 29 schema-invalid records; these are real model outputs, not missing data

**跳过的类别**

- `strategy_disagreement`：requires at least two selected strategies on independent
- `context_high_risk`：context strategy not selected for this intermediate export
- `context_low_risk`：context strategy not selected for this intermediate export

**总览**

| 编号 | 类别 | 数据集 | idx / pair_id | 项目 | CWE | 摘要 |
| --- | --- | --- | --- | --- | --- | --- |
| C-01 | 独立集误报（假阳性） | independent | `8632` | ImageMagick | CWE-772 | 独立集误报：idx=8632 标签为非漏洞，1/1 个可用策略预测为漏洞，平均置信度 0.900。 |
| C-02 | 独立集漏报（假阴性） | independent | `13796` | tensorflow | CWE-125, CWE-787 | 独立集漏报：idx=13796 标签为漏洞，1/1 个可用策略预测为非漏洞，平均置信度 0.950。 |
| C-03 | 配对 both_flagged（两侧均报漏洞） | pairs | `19923:19924` | keepalived | CWE-119 | 配对 both_flagged：pair_id=19923:19924，1/1 个可用策略给出该联合类别。 |
| C-04 | 配对 both_clean（两侧均判安全） | pairs | `25144:25145` | Android | CWE-264 | 配对 both_clean：pair_id=25144:25145，1/1 个可用策略给出该联合类别。 |
| C-05 | 配对判反（漏洞侧判安全、修复侧判漏洞） | pairs | `17834:17837` | rizin | CWE-787 | 配对 reversed：pair_id=17834:17837，1/1 个可用策略给出该联合类别。 |
| C-06 | 修复 schema 无效 | pairs | `10480:10481` | radare2 | CWE-119 | 修复 schema 无效：10480:10481 的 direct 输出未通过校验（schema_keys_mismatch）。 |
| C-07 | 修复完整且不同，但参考不匹配 | pairs | `22332:22334` | Chrome | CWE-79 | 修复完整且不同但参考不匹配：pair_id=22332:22334，与参考修复的行级相似度 0.598，差异行数 35。 |

**全局说明**

- Project/CWE/CVE/filepath/commit metadata is analysis-only; the runner never sends these fields to the model.
- Rationales are verbatim model text, not human audit conclusions.
- Reference-fixed matching is a normalized text comparison, not a repair-correctness oracle.
- Context non-empty status is correlated with the label in this dataset; context cases must not be read as causal evidence.
- Code excerpt line numbers are 1-based within the dedented function body, not source-file line numbers.
- No API call is made by this script; all values come from existing run artifacts and frozen split files.

## C-01 独立集误报（假阳性）

- **类别**：`independent_false_positive`
- **数据集**：`independent`
- **idx**：`8632`
- **pair_id**：`—`

**摘要**：独立集误报：idx=8632 标签为非漏洞，1/1 个可用策略预测为漏洞，平均置信度 0.900。

**关键事实**

- 标签：非漏洞。
- 错误预测的策略：direct；共识 1/1。
- 错误预测置信度：均值 0.900，范围 0.900–0.900。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 唯一函数（idx=8632，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`ImageMagick`；CWE=`CWE-772`；CVE=`CVE-2017-11310`；filepath=`coders/png.c`；commit=`8ca35831e91c3db8c6d281d09b605001003bec08`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | fp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > In the eXIf/exIf branch, the profile is allocated with chunk->size+6 bytes, but the code checks *p (uninitialized data) and may write 6 bytes of 'Exif\0\0' prefix, then copies chunk->size bytes. If the first byte happens to be 'E' but the rest isn't a valid Exif header, it returns; otherwise the 6-byte prefix plus chunk->size data fits exactly. However, the check `if (*p != 'E')` reads uninitialized memory and the logic is flawed: if the chunk data itself begins with 'E' but isn't a full Exif header, it errors out; more importantly, when the prefix is written, the buffer is exactly chunk->size+6, so the copy is in-bounds. The real issue is the uninitialized read of *p and p[1..5] before initialization, which is undefined behavior and can lead to incorrect handling. Additionally, the vpAg/caNv branches shift png_byte values (promoted to int) by 24 bits, which can overflow si … [truncated]

**代码摘录**

```c
    1 | static int read_user_chunk_callback(png_struct *ping, png_unknown_chunkp chunk)
    2 | {
    3 |   Image
    4 |     *image;
    5 | 
    6 | 
    7 |   /* The unknown chunk structure contains the chunk data:
    8 |      png_byte name[5];
    9 |      png_byte *data;
   10 |      png_size_t size;
   11 | 
   12 |      Note that libpng has already taken care of the CRC handling.
   13 | 
   14 |      Returns one of the following:
   15 |          return(-n);  chunk had an error
   16 |          return(0);  did not recognize
   17 |          return(n);  success
   18 |   */
   19 | 
   20 |   (void) LogMagickEvent(CoderEvent,GetMagickModule(),
   21 |      "    read_user_chunk: found %c%c%c%c chunk",
   22 |        chunk->name[0],chunk->name[1],chunk->name[2],chunk->name[3]);
   23 | 
   24 |   if (chunk->name[0]  == 101 &&
   25 |       (chunk->name[1] ==  88 || chunk->name[1] == 120 ) &&
   26 |       chunk->name[2] ==   73 &&
   27 |       chunk-> name[3] == 102)
   28 |     {
   29 |       /* process eXIf or exIf chunk */
… [110 lines omitted] …
  141 | 
  142 |       image->page.height=(size_t) ((chunk->data[4] << 24) |
  143 |          (chunk->data[5] << 16) | (chunk->data[6] << 8) | chunk->data[7]);
  144 | 
  145 |       image->page.x=(size_t) ((chunk->data[8] << 24) |
  146 |          (chunk->data[9] << 16) | (chunk->data[10] << 8) | chunk->data[11]);
  147 | 
  148 |       image->page.y=(size_t) ((chunk->data[12] << 24) |
  149 |          (chunk->data[13] << 16) | (chunk->data[14] << 8) | chunk->data[15]);
  150 | 
  151 |       return(1);
  152 |     }
  153 | 
  154 |   return(0); /* Did not recognize */
  155 | }
```


### 选择依据

- 规则：`independent_false_positive` — 独立集标签为 false，且至少一个可用策略预测 is_vulnerable=true；按错误预测的策略共识数、平均置信度和代码长度排序。
- 候选池：8；类别内排名：1；score=1084.750
- 评分组成：`{"consensus_term": 1000.0, "confidence_term": 90.0, "length_penalty": 5.25}`
- 去重：`reused_unit=False`

### 备注

- 标签来自冻结测试集；本脚本不做人工复核，也不把模型 rationale 当作事实。

## C-02 独立集漏报（假阴性）

- **类别**：`independent_false_negative`
- **数据集**：`independent`
- **idx**：`13796`
- **pair_id**：`—`

**摘要**：独立集漏报：idx=13796 标签为漏洞，1/1 个可用策略预测为非漏洞，平均置信度 0.950。

**关键事实**

- 标签：漏洞。
- 错误预测的策略：direct；共识 1/1。
- 错误预测置信度：均值 0.950，范围 0.950–0.950。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 唯一函数（idx=13796，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`tensorflow`；CWE=`CWE-125, CWE-787`；CVE=`CVE-2022-41900`；filepath=`tensorflow/core/ops/nn_ops_test.cc`；commit=`216525144ee7c910296f5b05d214ca1327c9ce48`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | fn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > This is a unit test for shape inference of fractional pooling ops; it contains no memory-unsafe operations or exploitable logic, only assertions on expected behavior.

**代码摘录**

```cpp
    1 | TEST(NNOpsTest, FractionalPool_ShapeFn) {
    2 |   for (const char* op_name : {"FractionalAvgPool", "FractionalMaxPool"}) {
    3 |     ShapeInferenceTestOp op(op_name);
    4 |     auto set_op = [&op, op_name](const std::vector<float>& pooling_ratio) {
    5 |       TF_ASSERT_OK(NodeDefBuilder("test", op_name)
    6 |                        .Input("input", 0, DT_FLOAT)
    7 |                        .Attr("pooling_ratio", pooling_ratio)
    8 |                        .Finalize(&op.node_def));
    9 |     };
   10 | 
   11 |     set_op(std::vector<float>{2.0f, 1, 1 / 1.5f, 1 / 2.0f});
   12 | 
   13 |     // Rank check.
   14 |     INFER_ERROR("must be rank 4", op, "[?,?,?]");
   15 | 
   16 |     // Unknown inputs.
   17 |     INFER_OK(op, "?", "[?,?,?,?];[?];[?]");
   18 |     INFER_OK(op, "[?,?,?,?]", "[?,?,?,?];[?];[?]");
   19 | 
   20 |     INFER_OK(op, "[10,20,30,40]", "[5,20,45,80];[20];[45]");
   21 |     INFER_OK(op, "[?,20,30,40]", "[?,20,45,80];[20];[45]");
   22 |     INFER_OK(op, "[10,?,30,40]", "[5,?,45,80];[?];[45]");
   23 |     INFER_OK(op, "[10,20,?,40]", "[5,20,?,80];[20];[?]");
   24 |     INFER_OK(op, "[10,20,30,?]", "[5,20,45,?];[20];[45]");
   25 | 
   26 |     // Wrong number of values for pooling_ratio.
   27 |     set_op(std::vector<float>{.5, 1.0, 1.5});
   28 |     INFER_ERROR("pooling_ratio field", op, "?");
   29 |     set_op(std::vector<float>{1, 2, 3, 4, 5});
   30 |     INFER_ERROR("pooling_ratio field", op, "?");
   31 | 
   32 |     // Check dim size >= 0.
   33 |     set_op(std::vector<float>{-1, 2, 3, 4});
   34 |     INFER_ERROR("is negative", op, "[1,2,3,4]");
   35 |   }
   36 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`false`；complete_and_changed=`false`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=False`, `whitespace_changed_from_input=False`, `fixed_line_count=36`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > The function is a test that only exercises shape inference with fixed, trusted inputs; it contains no memory-unsafe operations or exploitable security defect. The code is preserved unchanged.


### 选择依据

- 规则：`independent_false_negative` — 独立集标签为 true，且至少一个可用策略预测 is_vulnerable=false；按错误预测的策略共识数、平均置信度和代码长度排序。
- 候选池：90；类别内排名：1；score=1095.000
- 评分组成：`{"consensus_term": 1000.0, "confidence_term": 95.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 标签来自冻结测试集；漏报不等于函数一定可利用，需结合正文复核。

## C-03 配对 both_flagged（两侧均报漏洞）

- **类别**：`pair_both_flagged`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`19923:19924`

**摘要**：配对 both_flagged：pair_id=19923:19924，1/1 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=both_flagged。
- 目标类别 both_flagged 的策略数：1/1。
- 两侧平均置信度 0.875，最小置信度 0.850。
- 配对两侧 idx：vulnerable=19923, fixed=19924。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=19923，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`keepalived`；CWE=`CWE-119`；CVE=`CVE-2018-19115`；filepath=`lib/html.c`；commit=`f28015671a4b04785859d1b4b1327b367b6a10e9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | tp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > strncat copies up to inc bytes into a 10-byte buffer without accounting for the destination size, causing a heap buffer overflow if the status code field is longer than 9 bytes; also MALLOC result is not checked and buffer is not null-terminated.

**代码摘录**

```c
    1 |  int extract_status_code(char *buffer, size_t size)
    2 |  {
    3 | 	char *buf_code;
    4 | 	char *begin;
    5 |  	char *end = buffer + size;
    6 | 	size_t inc = 0;
    7 | 	int code;
    8 | 	/* Allocate the room */
    9 | 	buf_code = (char *)MALLOC(10);
   10 | 
   11 |  	/* Status-Code extraction */
   12 | 	while (buffer < end && *buffer++ != ' ') ;
   13 | 	begin = buffer;
   14 | 	while (buffer < end && *buffer++ != ' ')
   15 | 		inc++;
   16 | 	strncat(buf_code, begin, inc);
   17 | 	code = atoi(buf_code);
   18 | 	FREE(buf_code);
   19 |  	return code;
   20 |  }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=21`
- 参考修复：idx=19924；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.000
- 模型说明：
  > The original used strncat on an uninitialized MALLOC buffer, which reads uninitialized memory and can overflow if inc exceeds the 10-byte allocation. The fix uses a fixed stack buffer, bounds inc to its capacity, copies with memcpy, and null-terminates explicitly, preserving the extraction behavior while removing the overflow and uninitialized-read defects.


### 修复侧（idx=19924，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`keepalived`；CWE=`CWE-119`；CVE=`CVE-2018-19115`；filepath=`lib/html.c`；commit=`f28015671a4b04785859d1b4b1327b367b6a10e9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.850 | fp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.850）：
  > After the scan loop, buffer++ can move past end when no space/CR is found, and the subsequent buffer+3/end and *buffer dereferences can read out of bounds. The bounds check also uses >= which rejects valid cases and the pointer arithmetic can overflow.

**代码摘录**

```c
    1 |  int extract_status_code(char *buffer, size_t size)
    2 |  {
    3 |  	char *end = buffer + size;
    4 | 	unsigned long code;
    5 | 
    6 |  	/* Status-Code extraction */
    7 | 	while (buffer < end && *buffer != ' ' && *buffer != '\r')
    8 | 		buffer++;
    9 | 	buffer++;
   10 | 	if (buffer + 3 >= end || *buffer == ' ' || buffer[3] != ' ')
   11 | 		return 0;
   12 | 	code = strtoul(buffer, &end, 10);
   13 | 	if (buffer + 3 != end)
   14 | 		return 0;
   15 |  	return code;
   16 |  }
```


### 选择依据

- 规则：`pair_both_flagged` — 配对两侧均被同一策略判为漏洞；按同一联合类别的策略共识数、两侧平均/最小置信度和代码长度排序。
- 候选池：44；类别内排名：1；score=1104.500
- 评分组成：`{"consensus_term": 1000.0, "mean_confidence_term": 87.5, "min_confidence_term": 17.0, "reverse_confidence_bonus": 0.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；both_flagged 说明模型没有利用修复差异。

## C-04 配对 both_clean（两侧均判安全）

- **类别**：`pair_both_clean`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`25144:25145`

**摘要**：配对 both_clean：pair_id=25144:25145，1/1 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=both_clean。
- 目标类别 both_clean 的策略数：1/1。
- 两侧平均置信度 0.950，最小置信度 0.950。
- 配对两侧 idx：vulnerable=25144, fixed=25145。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=25144，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-264`；CVE=`CVE-2016-2496`；filepath=`services/inputflinger/InputWindow.cpp`；commit=`03a53d1c7765eeb3af0bc34c3dff02ada1953fbf`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | fn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > Simple bounds check with no memory access, arithmetic overflow, or untrusted pointer use; no security vulnerability.

**代码摘录**

```cpp
    1 | bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    2 |    return x >= frameLeft && x <= frameRight
    3 |            && y >= frameTop && y <= frameBottom;
    4 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=False`, `fixed_line_count=4`
- 参考修复：idx=25145；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.000
- 模型说明：
  > The function performs only bounded integer comparisons with no pointer arithmetic, array indexing, or memory access, so it contains no exploitable memory-safety defect. The original implementation is preserved unchanged.


### 修复侧（idx=25145，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-264`；CVE=`CVE-2016-2496`；filepath=`services/inputflinger/InputWindow.cpp`；commit=`03a53d1c7765eeb3af0bc34c3dff02ada1953fbf`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | tn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > Simple bounds check comparing integers against frame edges; no memory access, arithmetic overflow, or pointer issues. No security vulnerability.

**代码摘录**

```cpp
    1 | bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    2 |    return x >= frameLeft && x < frameRight
    3 |            && y >= frameTop && y < frameBottom;
    4 | }
```


### 选择依据

- 规则：`pair_both_clean` — 配对两侧均被同一策略判为非漏洞；排序规则同 both_flagged。
- 候选池：113；类别内排名：1；score=1111.380
- 评分组成：`{"consensus_term": 1000.0, "mean_confidence_term": 95.0, "min_confidence_term": 19.0, "reverse_confidence_bonus": 0.0, "length_penalty": 2.62}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；both_clean 说明模型漏掉了该对中的漏洞侧。

## C-05 配对判反（漏洞侧判安全、修复侧判漏洞）

- **类别**：`pair_reversed`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`17834:17837`

**摘要**：配对 reversed：pair_id=17834:17837，1/1 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=reversed。
- 目标类别 reversed 的策略数：1/1。
- 两侧平均置信度 0.650，最小置信度 0.600。
- 配对两侧 idx：vulnerable=17834, fixed=17837。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=17834，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`rizin`；CWE=`CWE-787`；CVE=`CVE-2022-36044`；filepath=`librz/bin/format/luac/luac_bin.c`；commit=`05bbd147caccc60162d6fba9baaaf24befa281cd`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.600 | fn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.600）：
  > The function checks allocation results and frees empty lists on failure, though it continues after list allocation failure (potential NULL deref in _luac_build_info/luac_add_entry). However, the lists are freed but not nulled, and execution continues, which could lead to use-after-free/NULL deref. This is a robustness concern but the primary allocation checks are present; no clear exploitable memory-safety bug is evident from the supplied code alone.

**代码摘录**

```c
    1 | LuacBinInfo *luac_build_info(LuaProto *proto) {
    2 | 	if (!proto) {
    3 | 		RZ_LOG_ERROR("Invalid luac file\n");
    4 | 		return NULL;
    5 | 	}
    6 | 
    7 | 	LuacBinInfo *ret = RZ_NEW0(LuacBinInfo);
    8 | 	if (!ret) {
    9 | 		return NULL;
   10 | 	}
   11 | 
   12 | 	ret->entry_list = rz_list_newf((RzListFree)free_rz_addr);
   13 | 	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
   14 | 	ret->section_list = rz_list_newf((RzListFree)free_rz_section);
   15 | 	ret->string_list = rz_list_newf((RzListFree)free_rz_string);
   16 | 
   17 | 	if (!(ret->entry_list && ret->symbol_list && ret->section_list && ret->string_list)) {
   18 | 		try_free_empty_list(ret->entry_list);
   19 | 		try_free_empty_list(ret->symbol_list);
   20 | 		try_free_empty_list(ret->section_list);
   21 | 		try_free_empty_list(ret->string_list);
   22 | 	}
   23 | 
   24 | 	_luac_build_info(proto, ret);
   25 | 
   26 | 	// add entry of main
   27 | 	ut64 main_entry_offset;
   28 | 	main_entry_offset = proto->code_offset + proto->code_skipped;
   29 | 	luac_add_entry(ret->entry_list, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);
   30 | 
   31 | 	return ret;
   32 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`invalid`；schema_valid=`false`
- complete_function=`n/a`；changed_from_input=`n/a`；complete_and_changed=`false`
- 校验错误：`repair JSON keys mismatch (missing=['explanation'], extra=[])`
- 结构校验：`schema_valid=False`
- 参考修复：idx=17837；不可比较（repair output is schema-invalid; reference text cannot be compared）


### 修复侧（idx=17837，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`rizin`；CWE=`CWE-787`；CVE=`CVE-2022-36044`；filepath=`librz/bin/format/luac/luac_bin.c`；commit=`05bbd147caccc60162d6fba9baaaf24befa281cd`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.700 | fp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.700）：
  > If any of the four rz_list_newf allocations fails, the lists are freed but the function continues to call _luac_build_info and luac_add_entry on the freed/NULL lists, leading to use-after-free/NULL dereference. It should return NULL after cleanup.

**代码摘录**

```c
    1 | LuacBinInfo *luac_build_info(LuaProto *proto) {
    2 | 	if (!proto) {
    3 | 		RZ_LOG_ERROR("Invalid luac file\n");
    4 | 		return NULL;
    5 | 	}
    6 | 
    7 | 	LuacBinInfo *ret = RZ_NEW0(LuacBinInfo);
    8 | 	if (!ret) {
    9 | 		return NULL;
   10 | 	}
   11 | 
   12 | 	ret->entry_list = rz_list_newf((RzListFree)free_rz_addr);
   13 | 	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
   14 | 	ret->section_list = rz_list_newf((RzListFree)free_rz_section);
   15 | 	ret->string_list = rz_list_newf((RzListFree)free_rz_string);
   16 | 
   17 | 	if (!(ret->entry_list && ret->symbol_list && ret->section_list && ret->string_list)) {
   18 | 		rz_list_free(ret->entry_list);
   19 | 		rz_list_free(ret->symbol_list);
   20 | 		rz_list_free(ret->section_list);
   21 | 		rz_list_free(ret->string_list);
   22 | 	}
   23 | 
   24 | 	_luac_build_info(proto, ret);
   25 | 
   26 | 	// add entry of main
   27 | 	ut64 main_entry_offset;
   28 | 	main_entry_offset = proto->code_offset + proto->code_skipped;
   29 | 	luac_add_entry(ret->entry_list, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);
   30 | 
   31 | 	return ret;
   32 | }
```


### 选择依据

- 规则：`pair_reversed` — 漏洞侧被判非漏洞且修复侧被判漏洞；排序规则同 both_flagged，并优先修复侧置信度高于漏洞侧的情形。
- 候选池：2；类别内排名：1；score=1077.000
- 评分组成：`{"consensus_term": 1000.0, "mean_confidence_term": 64.99999999999999, "min_confidence_term": 12.0, "reverse_confidence_bonus": 0.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；判反说明模型方向与参考修复相反。

## C-06 修复 schema 无效

- **类别**：`repair_schema_invalid`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`10480:10481`
- **聚焦侧**：`vulnerable`

**摘要**：修复 schema 无效：10480:10481 的 direct 输出未通过校验（schema_keys_mismatch）。

**关键事实**

- 修复记录策略：direct；状态：invalid；schema_valid=false。
- 校验错误：repair JSON keys mismatch (missing=['explanation'], extra=[])。
- 该错误在所选运行的无效修复记录中出现 45 次；原始模型响应长度 4391 字符。
- 配对两侧 idx：vulnerable=10480, fixed=10481。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=10480，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`radare2`；CWE=`CWE-119`；CVE=`CVE-2017-15385`；filepath=`libr/bin/format/elf/elf.c`；commit=`21a6f570ba33fa9f52f1bba87f07acc4e8c178f4`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | tp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > The function reads Verdef/Verdaux structures from the file into a heap buffer sized shdr->sh_size, but bounds checks compare against `end` using potentially overflowing pointer arithmetic (vstart + sizeof(...) > end) and the loop condition `(char*)defs + i < end` can be bypassed via integer overflow of i from vd_next. Also aux.vda_name is checked with `>` instead of `>=` against dynstr_size, allowing an out-of-bounds read at index == dynstr_size when passed to sdb_set. These permit out-of-bounds reads/writes on malformed ELF input.

**代码摘录**

```c
   17 | 	if (!defs) {
   18 | 		return false;
   19 | 	}
   20 | 	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
   21 | 		section_name = &bin->shstrtab[shdr->sh_name];
   22 | 	}
   23 | 	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
   24 | 		link_section_name = &bin->shstrtab[link_shdr->sh_name];
   25 | 	}
   26 | 	if (!defs) {
   27 | 		bprintf ("Warning: Cannot allocate memory (Check Elf_(Verdef))\n");
   28 | 		return NULL;
   29 | 	}
   30 | 	sdb = sdb_new0 ();
   31 | 	end = (char *)defs + shdr->sh_size;
   32 | 	sdb_set (sdb, "section_name", section_name, 0);
   33 | 	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
   34 | 	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
   35 | 	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
   36 | 	sdb_num_set (sdb, "link", shdr->sh_link, 0);
   37 | 	sdb_set (sdb, "link_section_name", link_section_name, 0);
   38 | 
   39 | 	for (cnt = 0, i = 0; cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {
   40 | 		Sdb *sdb_verdef = sdb_new0 ();
   41 | 		char *vstart = ((char*)defs) + i;
   42 | 		char key[32] = {0};
   43 | 		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
   44 | 		Elf_(Verdaux) aux = {0};
   45 | 		int j = 0;
   46 | 		int isum = 0;
   47 | 
   48 | 		r_buf_read_at (bin->b, shdr->sh_offset + i, dfs, sizeof (Elf_(Verdef)));
   49 | 		verdef->vd_version = READ16 (dfs, j)
   50 | 		verdef->vd_flags = READ16 (dfs, j)
   51 | 		verdef->vd_ndx = READ16 (dfs, j)
   52 | 		verdef->vd_cnt = READ16 (dfs, j)
   53 | 		verdef->vd_hash = READ32 (dfs, j)
   54 | 		verdef->vd_aux = READ32 (dfs, j)
   55 | 		verdef->vd_next = READ32 (dfs, j)
   56 | 		vstart += verdef->vd_aux;
   57 | 		if (vstart > end || vstart + sizeof (Elf_(Verdaux)) > end) {
   58 | 			sdb_free (sdb_verdef);
   59 | 			goto out_error;
   60 | 		}
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`invalid`；schema_valid=`false`
- complete_function=`n/a`；changed_from_input=`n/a`；complete_and_changed=`false`
- 校验错误：`repair JSON keys mismatch (missing=['explanation'], extra=[])`
- 结构校验：`schema_valid=False`
- 参考修复：idx=10481；不可比较（repair output is schema-invalid; reference text cannot be compared）
- 原始响应摘录（未解析）：

```json
{"fixed_function": "static Sdb *store_versioninfo_gnu_verdef(ELFOBJ *bin, Elf_(Shdr) *shdr, int sz) {\n\tconst char *section_name = \"\";\n\tconst char *link_section_name = \"\";\n\tchar *end = NULL;\n\tElf_(Shdr) *link_shdr = NULL;\n\tut8 dfs[sizeof (Elf_(Verdef))] = {0};\n\tSdb *sdb = NULL;\n\tint cnt, i;\n\tElf_(Verdef) *defs = NULL;\n\n\tif (!bin || !shdr) {\n\t\treturn NULL;\n\t}\n\tif (shdr->sh_link >= bin->ehdr.e_shnum) {\n\t\treturn NULL;\n\t}\n\tlink_shdr = &bin->shdr[shdr->sh_link];\n\tif (shdr->sh_size < 1 || shdr->sh_size > ST32_MAX) {\n\t\treturn NULL;\n\t}\n\tdefs = calloc (shdr->sh_size, sizeof (char));\n\tif (!defs) {\n\t\tbprintf (\"Warning: Cannot allocate memory (Check Elf_(Verdef))\\n\");\n\t\treturn NULL;\n\t}\n\tif (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {\n\t\tsection_name = &bin->shstrtab[shdr->sh_name];\n\t}\n\tif (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {\n\t\tlink_section_name = &bin->shstrtab[link_shdr->sh_name];\n\t}\n\tsdb = sdb_new0 ();\n\tif (!sdb) {\n\t\tfree (defs);\n\t\treturn NULL;\n\t}\n\tend = (char *)defs + shdr->sh_size;\n\tsdb_set (sdb, \"section_name\", section_name, 0);\n\tsdb_num_set (sdb, \"entries\", shdr->sh_info, 0);\n\tsdb_num_set (sdb, \"addr\", shdr->sh_addr, 0);\n\tsdb_num_set (sdb, \"offset\", shdr->sh_offset, 0);\n\tsdb_num_set (sdb, \"link\", shdr->sh_link, 0);\n\tsdb_set (sdb, \"link_section_name\", link_section_name, 0);\n\n\tfor (cnt = 0, i = 0; cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {\n\t\tSdb *sdb_verdef = sdb_new0 ();\n\t\tchar *vstart = ( … [truncated]
```


### 修复侧（idx=10481，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`radare2`；CWE=`CWE-119`；CVE=`CVE-2017-15385`；filepath=`libr/bin/format/elf/elf.c`；commit=`21a6f570ba33fa9f52f1bba87f07acc4e8c178f4`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | fp | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > Multiple out-of-bounds issues: sh_link check uses > instead of >= allowing index == e_shnum; aux.vda_name compared with > dynstr_size (off-by-one) then used to index dynstr; vstart bounds checks use pointer arithmetic that can overflow; and the loop reads Verdef fields from a calloc'd buffer without validating sh_offset+i against file size. These allow OOB reads/writes on malformed ELF input.

**代码摘录**

```c
   17 | 	if (!defs) {
   18 | 		return false;
   19 | 	}
   20 | 	if (bin->shstrtab && shdr->sh_name < bin->shstrtab_size) {
   21 | 		section_name = &bin->shstrtab[shdr->sh_name];
   22 | 	}
   23 | 	if (link_shdr && bin->shstrtab && link_shdr->sh_name < bin->shstrtab_size) {
   24 | 		link_section_name = &bin->shstrtab[link_shdr->sh_name];
   25 | 	}
   26 | 	if (!defs) {
   27 | 		bprintf ("Warning: Cannot allocate memory (Check Elf_(Verdef))\n");
   28 | 		return NULL;
   29 | 	}
   30 | 	sdb = sdb_new0 ();
   31 | 	end = (char *)defs + shdr->sh_size;
   32 | 	sdb_set (sdb, "section_name", section_name, 0);
   33 | 	sdb_num_set (sdb, "entries", shdr->sh_info, 0);
   34 | 	sdb_num_set (sdb, "addr", shdr->sh_addr, 0);
   35 | 	sdb_num_set (sdb, "offset", shdr->sh_offset, 0);
   36 | 	sdb_num_set (sdb, "link", shdr->sh_link, 0);
   37 | 	sdb_set (sdb, "link_section_name", link_section_name, 0);
   38 | 
   39 | 	for (cnt = 0, i = 0; i >= 0 && cnt < shdr->sh_info && ((char *)defs + i < end); ++cnt) {
   40 | 		Sdb *sdb_verdef = sdb_new0 ();
   41 | 		char *vstart = ((char*)defs) + i;
   42 | 		char key[32] = {0};
   43 | 		Elf_(Verdef) *verdef = (Elf_(Verdef)*)vstart;
   44 | 		Elf_(Verdaux) aux = {0};
   45 | 		int j = 0;
   46 | 		int isum = 0;
   47 | 
   48 | 		r_buf_read_at (bin->b, shdr->sh_offset + i, dfs, sizeof (Elf_(Verdef)));
   49 | 		verdef->vd_version = READ16 (dfs, j)
   50 | 		verdef->vd_flags = READ16 (dfs, j)
   51 | 		verdef->vd_ndx = READ16 (dfs, j)
   52 | 		verdef->vd_cnt = READ16 (dfs, j)
   53 | 		verdef->vd_hash = READ32 (dfs, j)
   54 | 		verdef->vd_aux = READ32 (dfs, j)
   55 | 		verdef->vd_next = READ32 (dfs, j)
   56 | 		vstart += verdef->vd_aux;
   57 | 		if (vstart > end || vstart + sizeof (Elf_(Verdaux)) > end) {
   58 | 			sdb_free (sdb_verdef);
   59 | 			goto out_error;
   60 | 		}
```


### 选择依据

- 规则：`repair_schema_invalid` — 修复记录 status=invalid 且 schema_valid=false；优先选择所选运行中最常见错误类型，并优先有参考修复的配对样本。
- 候选池：48；类别内排名：1；score=4607.330
- 评分组成：`{"error_frequency_term": 4500.0, "content_term": 100.0, "reference_bonus": 10.0, "length_penalty": 2.67}`
- 去重：`reused_unit=False`

### 备注

- Schema-invalid output is a format/engineering failure, not a repair-quality label.
- schema 无效是工程/格式失败，不能与“修复错误”或“修复正确”混为一谈。

## C-07 修复完整且不同，但参考不匹配

- **类别**：`repair_complete_reference_mismatch`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`22332:22334`
- **聚焦侧**：`vulnerable`

**摘要**：修复完整且不同但参考不匹配：pair_id=22332:22334，与参考修复的行级相似度 0.598，差异行数 35。

**关键事实**

- 修复策略：direct；complete_function=true；changed_from_input=true。
- 与参考修复的规范化文本不相等；行级相似度 0.598，差异行数 35。
- 参考修复 idx：22334。
- 配对两侧 idx：vulnerable=22332, fixed=22334。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=22332，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Chrome`；CWE=`CWE-79`；CVE=`CVE-2016-5164`；filepath=`third_party/WebKit/Source/platform/v8_inspector/V8Console.cpp`；commit=`93bc623489bdcfc7e9127614fcfb3258edf3f0f9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.600 | fn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.600）：
  > This is a console object factory that creates bound function properties and accessors on a fresh V8 object. It uses standard V8 APIs with checked results (ToLocalChecked, FromMaybe) and no obvious memory-safety issue; the DCHECK on SetPrototype is only a debug assertion but failure is benign. No clear exploitable vulnerability is evident from the supplied code.

**代码摘录**

```cpp
    1 | v8::Local<v8::Object> V8Console::createConsole(InspectedContext* inspectedContext, bool hasMemoryAttribute)
    2 | {
    3 |     v8::Local<v8::Context> context = inspectedContext->context();
    4 |     v8::Context::Scope contextScope(context);
    5 |     v8::Isolate* isolate = context->GetIsolate();
    6 |      v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
    7 | 
    8 |      v8::Local<v8::Object> console = v8::Object::New(isolate);
    9 | 
   10 |      createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
   11 |      createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
   12 |     createBoundFunctionProperty(context, console, "info", V8Console::infoCallback);
   13 |     createBoundFunctionProperty(context, console, "log", V8Console::logCallback);
   14 |     createBoundFunctionProperty(context, console, "warn", V8Console::warnCallback);
   15 |     createBoundFunctionProperty(context, console, "dir", V8Console::dirCallback);
   16 |     createBoundFunctionProperty(context, console, "dirxml", V8Console::dirxmlCallback);
   17 |     createBoundFunctionProperty(context, console, "table", V8Console::tableCallback);
   18 |     createBoundFunctionProperty(context, console, "trace", V8Console::traceCallback);
   19 |     createBoundFunctionProperty(context, console, "group", V8Console::groupCallback);
   20 |     createBoundFunctionProperty(context, console, "groupCollapsed", V8Console::groupCollapsedCallback);
   21 |     createBoundFunctionProperty(context, console, "groupEnd", V8Console::groupEndCallback);
   22 |     createBoundFunctionProperty(context, console, "clear", V8Console::clearCallback);
   23 |     createBoundFunctionProperty(context, console, "count", V8Console::countCallback);
   24 |     createBoundFunctionProperty(context, console, "assert", V8Console::assertCallback);
   25 |     createBoundFunctionProperty(context, console, "markTimeline", V8Console::markTimelineCallback);
   26 |     createBoundFunctionProperty(context, console, "profile", V8Console::profileCallback);
   27 |     createBoundFunctionProperty(context, console, "profileEnd", V8Console::profileEndCallback);
   28 |     createBoundFunctionProperty(context, console, "timeline", V8Console::timelineCallback);
   29 |     createBoundFunctionProperty(context, console, "timelineEnd", V8Console::timelineEndCallback);
   30 |     createBoundFunctionProperty(context, console, "time", V8Console::timeCallback);
   31 |      createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
   32 |      createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
   33 | 
   34 |     bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
   35 |     DCHECK(success);
   36 |      if (hasMemoryAttribute)
   37 |          console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked(), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::…
   38 | 
   39 |     console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext));
   40 |     return console;
   41 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=46`
- 参考修复：idx=22334；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.598
- 模型说明：
  > The original code ignored the Maybe<bool> results of SetAccessorProperty and SetPrivate, which can fail (e.g., if the object is non-extensible or the private key is invalid), leading to unchecked failures. The fix captures and checks these results with DCHECK, matching the existing pattern used for SetPrototype, while preserving the same behavior and signature.
- 相对原函数的 diff（+18/-13 行）：

```diff
--- original_vulnerable
+++ model_fixed_function
@@ -3,12 +3,12 @@
     v8::Local<v8::Context> context = inspectedContext->context();
     v8::Context::Scope contextScope(context);
     v8::Isolate* isolate = context->GetIsolate();
-     v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
- 
-     v8::Local<v8::Object> console = v8::Object::New(isolate);
- 
-     createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
-     createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
+    v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
+
+    v8::Local<v8::Object> console = v8::Object::New(isolate);
+
+    createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
+    createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
     createBoundFunctionProperty(context, console, "info", V8Console::infoCallback);
     createBoundFunctionProperty(context, console, "log", V8Console::logCallback);
     createBoundFunctionProperty(context, console, "warn", V8Console::warnCallback);
@@ -28,14 +28,19 @@
     createBoundFunctionProperty(context, console, "timeline", V8Console::timelineCallback);
     createBoundFunctionProperty(context, console, "timelineEnd", V8Console::timelineEndCallback);
     createBoundFunctionProperty(context, console, "time", V8Console::timeCallback);
-     createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
-     createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
- 
+    createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
+    createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
+
     bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
     DCHECK(success);
-     if (hasMemoryAttribute)
-         console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked(), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memorySetterCallback, v8::Local<v8::Value>(), 0).ToLocalChecked(), static_cast<v8::PropertyAttribute>(v8::None), v8::DEFAULT);
- 
-    console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext));
+    if (hasMemoryAttribute) {
+        v8::Local<v8::Function> getter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked();
+        v8::Local<v8::Function> setter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memorySetterCallback, v8::Local<v8::Value>(), 0).ToLocalChecked();
+        success = console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), getter, setter, static_cast<v8::PropertyAttribute>(v8::None), v8::DEFAULT).FromMaybe(false);
+        DCHECK(success);
+    }
+
+    success = console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext)).FromMaybe(false);
+    DCHECK(success);
     return console;
 }
```

- 相对参考修复的 diff（+15/-20 行）：

```diff
--- model_fixed_function
+++ reference_fixed
@@ -3,12 +3,14 @@
     v8::Local<v8::Context> context = inspectedContext->context();
     v8::Context::Scope contextScope(context);
     v8::Isolate* isolate = context->GetIsolate();
-    v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
-
-    v8::Local<v8::Object> console = v8::Object::New(isolate);
-
-    createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
-    createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
+     v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
+ 
+     v8::Local<v8::Object> console = v8::Object::New(isolate);
+    bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
+    DCHECK(success);
+ 
+     createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
+     createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
     createBoundFunctionProperty(context, console, "info", V8Console::infoCallback);
     createBoundFunctionProperty(context, console, "log", V8Console::logCallback);
     createBoundFunctionProperty(context, console, "warn", V8Console::warnCallback);
@@ -28,19 +30,12 @@
     createBoundFunctionProperty(context, console, "timeline", V8Console::timelineCallback);
     createBoundFunctionProperty(context, console, "timelineEnd", V8Console::timelineEndCallback);
     createBoundFunctionProperty(context, console, "time", V8Console::timeCallback);
-    createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
-    createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
-
-    bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
-    DCHECK(success);
-    if (hasMemoryAttribute) {
-        v8::Local<v8::Function> getter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked();
-        v8::Local<v8::Function> setter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memorySetterCallback, v8::Local<v8::Value>(), 0).ToLocalChecked();
-        success = console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), getter, setter, static_cast<v8::PropertyAttribute>(v8::None), v8::DEFAULT).FromMaybe(false);
-        DCHECK(success);
-    }
-
-    success = console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext)).FromMaybe(false);
-    DCHECK(success);
+     createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
+     createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
+ 
+     if (hasMemoryAttribute)
+         console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked(), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memorySetterCallback, v8::Local<v8::Value>(), 0).ToLocalChecked(), static_cast<v8::PropertyAttribute>(v8::None), v8::DEFAULT);
+ 
+    console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext));
     return console;
 }
```

- 模型修复函数摘录：

```c
    1 | v8::Local<v8::Object> V8Console::createConsole(InspectedContext* inspectedContext, bool hasMemoryAttribute)
    2 | {
    3 |     v8::Local<v8::Context> context = inspectedContext->context();
    4 |     v8::Context::Scope contextScope(context);
    5 |     v8::Isolate* isolate = context->GetIsolate();
    6 |     v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
    7 | 
    8 |     v8::Local<v8::Object> console = v8::Object::New(isolate);
    9 | 
   10 |     createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
   11 |     createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
   12 |     createBoundFunctionProperty(context, console, "info", V8Console::infoCallback);
   13 |     createBoundFunctionProperty(context, console, "log", V8Console::logCallback);
   14 |     createBoundFunctionProperty(context, console, "warn", V8Console::warnCallback);
   15 |     createBoundFunctionProperty(context, console, "dir", V8Console::dirCallback);
   16 |     createBoundFunctionProperty(context, console, "dirxml", V8Console::dirxmlCallback);
   17 |     createBoundFunctionProperty(context, console, "table", V8Console::tableCallback);
   18 |     createBoundFunctionProperty(context, console, "trace", V8Console::traceCallback);
   19 |     createBoundFunctionProperty(context, console, "group", V8Console::groupCallback);
   20 |     createBoundFunctionProperty(context, console, "groupCollapsed", V8Console::groupCollapsedCallback);
   21 |     createBoundFunctionProperty(context, console, "groupEnd", V8Console::groupEndCallback);
   22 |     createBoundFunctionProperty(context, console, "clear", V8Console::clearCallback);
   23 |     createBoundFunctionProperty(context, console, "count", V8Console::countCallback);
   24 |     createBoundFunctionProperty(context, console, "assert", V8Console::assertCallback);
   25 |     createBoundFunctionProperty(context, console, "markTimeline", V8Console::markTimelineCallback);
   26 |     createBoundFunctionProperty(context, console, "profile", V8Console::profileCallback);
   27 |     createBoundFunctionProperty(context, console, "profileEnd", V8Console::profileEndCallback);
   28 |     createBoundFunctionProperty(context, console, "timeline", V8Console::timelineCallback);
   29 |     createBoundFunctionProperty(context, console, "timelineEnd", V8Console::timelineEndCallback);
   30 |     createBoundFunctionProperty(context, console, "time", V8Console::timeCallback);
   31 |     createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
   32 |     createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
   33 | 
   34 |     bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
   35 |     DCHECK(success);
   36 |     if (hasMemoryAttribute) {
   37 |         v8::Local<v8::Function> getter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked();
   38 |         v8::Local<v8::Function> setter = V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memorySetterCallback, v8::Local<v8::Value>(), 0).ToLocalChecked();
   39 |         success = console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), getter, setter, static_cast<v8::PropertyAttribute>(v8::None), v8::DEFAULT).FromMaybe(false);
   40 |         DCHECK(success);
   41 |     }
   42 | 
   43 |     success = console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext)).FromMaybe(false);
   44 |     DCHECK(success);
   45 |     return console;
```


### 修复侧（idx=22334，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Chrome`；CWE=`CWE-79`；CVE=`CVE-2016-5164`；filepath=`third_party/WebKit/Source/platform/v8_inspector/V8Console.cpp`；commit=`93bc623489bdcfc7e9127614fcfb3258edf3f0f9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.700 | tn | unused |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.700）：
  > This is V8 inspector console setup code. It creates a console object and binds callbacks; no obvious memory-safety issue (no unchecked indexing, buffer handling, or user-controlled length). SetPrototype failure is only DCHECK'd but not security-relevant. No clear exploitable vulnerability in the supplied function.

**代码摘录**

```cpp
    1 | v8::Local<v8::Object> V8Console::createConsole(InspectedContext* inspectedContext, bool hasMemoryAttribute)
    2 | {
    3 |     v8::Local<v8::Context> context = inspectedContext->context();
    4 |     v8::Context::Scope contextScope(context);
    5 |     v8::Isolate* isolate = context->GetIsolate();
    6 |      v8::MicrotasksScope microtasksScope(isolate, v8::MicrotasksScope::kDoNotRunMicrotasks);
    7 | 
    8 |      v8::Local<v8::Object> console = v8::Object::New(isolate);
    9 |     bool success = console->SetPrototype(context, v8::Object::New(isolate)).FromMaybe(false);
   10 |     DCHECK(success);
   11 | 
   12 |      createBoundFunctionProperty(context, console, "debug", V8Console::debugCallback);
   13 |      createBoundFunctionProperty(context, console, "error", V8Console::errorCallback);
   14 |     createBoundFunctionProperty(context, console, "info", V8Console::infoCallback);
   15 |     createBoundFunctionProperty(context, console, "log", V8Console::logCallback);
   16 |     createBoundFunctionProperty(context, console, "warn", V8Console::warnCallback);
   17 |     createBoundFunctionProperty(context, console, "dir", V8Console::dirCallback);
   18 |     createBoundFunctionProperty(context, console, "dirxml", V8Console::dirxmlCallback);
   19 |     createBoundFunctionProperty(context, console, "table", V8Console::tableCallback);
   20 |     createBoundFunctionProperty(context, console, "trace", V8Console::traceCallback);
   21 |     createBoundFunctionProperty(context, console, "group", V8Console::groupCallback);
   22 |     createBoundFunctionProperty(context, console, "groupCollapsed", V8Console::groupCollapsedCallback);
   23 |     createBoundFunctionProperty(context, console, "groupEnd", V8Console::groupEndCallback);
   24 |     createBoundFunctionProperty(context, console, "clear", V8Console::clearCallback);
   25 |     createBoundFunctionProperty(context, console, "count", V8Console::countCallback);
   26 |     createBoundFunctionProperty(context, console, "assert", V8Console::assertCallback);
   27 |     createBoundFunctionProperty(context, console, "markTimeline", V8Console::markTimelineCallback);
   28 |     createBoundFunctionProperty(context, console, "profile", V8Console::profileCallback);
   29 |     createBoundFunctionProperty(context, console, "profileEnd", V8Console::profileEndCallback);
   30 |     createBoundFunctionProperty(context, console, "timeline", V8Console::timelineCallback);
   31 |     createBoundFunctionProperty(context, console, "timelineEnd", V8Console::timelineEndCallback);
   32 |     createBoundFunctionProperty(context, console, "time", V8Console::timeCallback);
   33 |      createBoundFunctionProperty(context, console, "timeEnd", V8Console::timeEndCallback);
   34 |      createBoundFunctionProperty(context, console, "timeStamp", V8Console::timeStampCallback);
   35 | 
   36 |      if (hasMemoryAttribute)
   37 |          console->SetAccessorProperty(toV8StringInternalized(isolate, "memory"), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::memoryGetterCallback, console, 0).ToLocalChecked(), V8_FUNCTION_NEW_REMOVE_PROTOTYPE(context, V8Console::…
   38 | 
   39 |     console->SetPrivate(context, inspectedContextPrivateKey(isolate), v8::External::New(isolate, inspectedContext));
   40 |     return console;
   41 | }
```


### 选择依据

- 规则：`repair_complete_reference_mismatch` — 配对修复记录 schema 有效、complete_function=true、changed_from_input=true，且规范化文本与参考修复不相等；按文本差异度、改动行数和结构校验排序。
- 候选池：104；类别内排名：1；score=228.845
- 评分组成：`{"similarity_target": 0.6, "similarity_distance": 0.0022988505747125743, "similarity_term": 199.5402298850575, "diff_line_term": 20.0, "structural_bonus": 10.0, "length_penalty": 0.695}`
- 去重：`reused_unit=False`

### 备注

- Reference mismatch is a text comparison, not proof that the repair is incorrect.
- 参考不匹配是规范化文本比较的结果，不是修复错误或安全等价性的证明；完整且不同也可能是另一种有效修复。
