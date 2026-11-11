# SecVulEval 定性案例（正式导出）

- 生成时间（UTC）：`2026-11-11T12:13:10.555493+00:00`
- 脚本版本：`qualitative-v1`
- 模式：`formal`；formal=`True`
- 实际使用策略/数据集：`independent=direct,few-shot,context；pairs=direct,few-shot,context`
- 案例数：10
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
- test_v1_few-shot_independent: 1 schema-invalid records; these are real model outputs, not missing data
- test_v1_few-shot_pairs: 2 schema-invalid records; these are real model outputs, not missing data
- test_v1_context_independent: 20 schema-invalid records; these are real model outputs, not missing data
- test_v1_context_pairs: 31 schema-invalid records; these are real model outputs, not missing data

**总览**

| 编号 | 类别 | 数据集 | idx / pair_id | 项目 | CWE | 摘要 |
| --- | --- | --- | --- | --- | --- | --- |
| C-01 | 独立集误报（假阳性） | independent | `8632` | ImageMagick | CWE-772 | 独立集误报：idx=8632 标签为非漏洞，3/3 个可用策略预测为漏洞，平均置信度 0.917。 |
| C-02 | 独立集漏报（假阴性） | independent | `13796` | tensorflow | CWE-125, CWE-787 | 独立集漏报：idx=13796 标签为漏洞，3/3 个可用策略预测为非漏洞，平均置信度 0.950。 |
| C-03 | 策略分歧 | independent | `2548` | linux | CWE-476 | 策略分歧：idx=2548 上 direct=非漏洞(0.600)，few-shot=漏洞(0.900)，context=漏洞(0.750)。 |
| C-04 | 配对 both_flagged（两侧均报漏洞） | pairs | `19923:19924` | keepalived | CWE-119 | 配对 both_flagged：pair_id=19923:19924，3/3 个可用策略给出该联合类别。 |
| C-05 | 配对 both_clean（两侧均判安全） | pairs | `25144:25145` | Android | CWE-264 | 配对 both_clean：pair_id=25144:25145，3/3 个可用策略给出该联合类别。 |
| C-06 | 配对判反（漏洞侧判安全、修复侧判漏洞） | pairs | `15922:15928` | pjproject | CWE-120 | 配对 reversed：pair_id=15922:15928，1/3 个可用策略给出该联合类别。 |
| C-07 | 修复 schema 无效 | pairs | `10480:10481` | radare2 | CWE-119 | 修复 schema 无效：10480:10481 的 direct 输出未通过校验（schema_keys_mismatch）。 |
| C-08 | 修复完整且不同，但参考不匹配 | pairs | `25161:25163` | Android | CWE-20 | 修复完整且不同但参考不匹配：pair_id=25161:25163，与参考修复的行级相似度 0.605，差异行数 47。 |
| C-09 | context 高风险判定 | pairs | `679:680` | linux | CWE-20 | context 高风险判定：679:680 的 vulnerable 侧，is_vulnerable=True，置信度 0.900，标签=漏洞，上下文非空=True。 |
| C-10 | context 低风险判定 | pairs | `16915:16937` | relic | CWE-190 | context 低风险判定：16915:16937 的 fixed 侧，is_vulnerable=False，置信度 0.900，标签=非漏洞，上下文非空=True。 |

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

**摘要**：独立集误报：idx=8632 标签为非漏洞，3/3 个可用策略预测为漏洞，平均置信度 0.917。

**关键事实**

- 标签：非漏洞。
- 错误预测的策略：direct, few-shot, context；共识 3/3。
- 错误预测置信度：均值 0.917，范围 0.900–0.950。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 唯一函数（idx=8632，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`ImageMagick`；CWE=`CWE-772`；CVE=`CVE-2017-11310`；filepath=`coders/png.c`；commit=`8ca35831e91c3db8c6d281d09b605001003bec08`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | fp | unused |
| few-shot | 漏洞 | 0.950 | fp | unused |
| context | 漏洞 | 0.900 | fp | used |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > In the eXIf/exIf branch, the profile is allocated with chunk->size+6 bytes, but the code checks *p (uninitialized data) and may write 6 bytes of 'Exif\0\0' prefix, then copies chunk->size bytes. If the first byte happens to be 'E' but the rest isn't a valid Exif header, it returns; otherwise the 6-byte prefix plus chunk->size data fits exactly. However, the check `if (*p != 'E')` reads uninitialized memory and the logic is flawed: if the chunk data itself begins with 'E' but isn't a full Exif header, it errors out; more importantly, when the prefix is written, the buffer is exactly chunk->size+6, so the copy is in-bounds. The real issue is the uninitialized read of *p and p[1..5] before initialization, which is undefined behavior and can lead to incorrect handling. Additionally, the vpAg/caNv branches shift png_byte values (promoted to int) by 24 bits, which can overflow si … [truncated]
- **few-shot**（漏洞，confidence=0.950）：
  > In the eXIf branch, the profile is allocated with chunk->size+6 bytes, but the code first writes the 6-byte Exif header and then copies chunk->size bytes, overflowing the buffer by 6 bytes.
- **context**（漏洞，confidence=0.900）：
  > In the eXIf/exIf branch, the profile is allocated with chunk->size+6 bytes, but if the chunk data already begins with 'E' the code does not advance p past the 6-byte Exif header; it then copies chunk->size bytes starting at p, writing up to 6 bytes past the allocated buffer (heap overflow). Also the 'E' check reads uninitialized/zero-length data and the header validation is inconsistent.

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
- 候选池：9；类别内排名：1；score=1086.417
- 评分组成：`{"consensus_term": 1000.0, "confidence_term": 91.66666666666666, "length_penalty": 5.25}`
- 去重：`reused_unit=False`

### 备注

- 标签来自冻结测试集；本脚本不做人工复核，也不把模型 rationale 当作事实。

## C-02 独立集漏报（假阴性）

- **类别**：`independent_false_negative`
- **数据集**：`independent`
- **idx**：`13796`
- **pair_id**：`—`

**摘要**：独立集漏报：idx=13796 标签为漏洞，3/3 个可用策略预测为非漏洞，平均置信度 0.950。

**关键事实**

- 标签：漏洞。
- 错误预测的策略：direct, few-shot, context；共识 3/3。
- 错误预测置信度：均值 0.950，范围 0.950–0.950。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 唯一函数（idx=13796，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`tensorflow`；CWE=`CWE-125, CWE-787`；CVE=`CVE-2022-41900`；filepath=`tensorflow/core/ops/nn_ops_test.cc`；commit=`216525144ee7c910296f5b05d214ca1327c9ce48`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | fn | unused |
| few-shot | 非漏洞 | 0.950 | fn | unused |
| context | 非漏洞 | 0.950 | fn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > This is a unit test for shape inference of fractional pooling ops; it contains no memory-unsafe operations or exploitable logic, only assertions on expected behavior.
- **few-shot**（非漏洞，confidence=0.950）：
  > This is a unit test that builds node definitions and checks shape inference results. It contains no production parsing, memory handling, or untrusted input processing.
- **context**（非漏洞，confidence=0.950）：
  > This is a unit test for shape inference of fractional pooling ops; it only exercises validation logic and contains no memory-unsafe operations or exploitable code paths.

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

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`false`；complete_and_changed=`false`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=False`, `whitespace_changed_from_input=False`, `fixed_line_count=36`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > The test is already safe; the only change is to keep the function intact. No security defect is present in this test code, so the function is returned unchanged.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`false`；complete_and_changed=`false`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=False`, `whitespace_changed_from_input=False`, `fixed_line_count=36`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > The original test function contains no memory-unsafe operations; it is a unit test using safe C++ constructs (range-for over string literals, lambdas, std::vector). The only potential concern is the integer division in `1 / 1.5f` and `1 / 2.0f`, but these are floating-point divisions producing valid float values, not security defects. The function is preserved unchanged as it already avoids buffer overflows, use-after-free, and other memory-safety issues.


### 选择依据

- 规则：`independent_false_negative` — 独立集标签为 true，且至少一个可用策略预测 is_vulnerable=false；按错误预测的策略共识数、平均置信度和代码长度排序。
- 候选池：95；类别内排名：1；score=1095.000
- 评分组成：`{"consensus_term": 1000.0, "confidence_term": 94.99999999999999, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 标签来自冻结测试集；漏报不等于函数一定可利用，需结合正文复核。

## C-03 策略分歧

- **类别**：`strategy_disagreement`
- **数据集**：`independent`
- **idx**：`2548`
- **pair_id**：`—`

**摘要**：策略分歧：idx=2548 上 direct=非漏洞(0.600)，few-shot=漏洞(0.900)，context=漏洞(0.750)。

**关键事实**

- 有效预测的策略数：3；不同预测类别数：2。
- 置信度跨度：0.300。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 唯一函数（idx=2548，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`linux`；CWE=`CWE-476`；CVE=`CVE-2018-5333`；filepath=`net/rds/rdma.c`；commit=`7d11f77f84b27cef452cee332f4e469503084737`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.600 | fn | unused |
| few-shot | 漏洞 | 0.900 | tp | unused |
| context | 漏洞 | 0.750 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.600）：
  > The function validates cmsg_len before reading args, checks op_active to prevent double-set, verifies 8-byte alignment, and cleans up page/notifier on error. The BUG() on default is only reachable if callers pass an unexpected cmsg_type, which is a robustness concern rather than a memory-safety vulnerability in this function.
- **few-shot**（漏洞，confidence=0.900）：
  > The error path frees rm->atomic.op_notifier without clearing it, and op_active is already set. A later cleanup or second call can free the same pointer again, causing a double free.
- **context**（漏洞，confidence=0.750）：
  > The function pins a user-supplied page via rds_pin_pages and stores it in op_sg, but on the error path it calls put_page(page) while the page is still referenced by op_sg, and it does not clear op_sg/op_notifier, leading to a use-after-free/double-free when the message is later released. Also op_active is set before validation, and the error path frees op_notifier without nulling it.

**代码摘录**

```c
    1 | int rds_cmsg_atomic(struct rds_sock *rs, struct rds_message *rm,
    2 | 		    struct cmsghdr *cmsg)
    3 | {
    4 | 	struct page *page = NULL;
    5 | 	struct rds_atomic_args *args;
    6 | 	int ret = 0;
    7 | 
    8 | 	if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct rds_atomic_args))
    9 | 	 || rm->atomic.op_active)
   10 | 		return -EINVAL;
   11 | 
   12 | 	args = CMSG_DATA(cmsg);
   13 | 
   14 | 	/* Nonmasked & masked cmsg ops converted to masked hw ops */
   15 | 	switch (cmsg->cmsg_type) {
   16 | 	case RDS_CMSG_ATOMIC_FADD:
   17 | 		rm->atomic.op_type = RDS_ATOMIC_TYPE_FADD;
   18 | 		rm->atomic.op_m_fadd.add = args->fadd.add;
   19 | 		rm->atomic.op_m_fadd.nocarry_mask = 0;
   20 | 		break;
   21 | 	case RDS_CMSG_MASKED_ATOMIC_FADD:
   22 | 		rm->atomic.op_type = RDS_ATOMIC_TYPE_FADD;
   23 | 		rm->atomic.op_m_fadd.add = args->m_fadd.add;
   24 | 		rm->atomic.op_m_fadd.nocarry_mask = args->m_fadd.nocarry_mask;
   25 | 		break;
   26 | 	case RDS_CMSG_ATOMIC_CSWP:
   27 | 		rm->atomic.op_type = RDS_ATOMIC_TYPE_CSWP;
   28 | 		rm->atomic.op_m_cswp.compare = args->cswp.compare;
   29 | 		rm->atomic.op_m_cswp.swap = args->cswp.swap;
   30 | 		rm->atomic.op_m_cswp.compare_mask = ~0;
… [48 lines omitted] …
   79 | 		rm->atomic.op_notifier->n_user_token = args->user_token;
   80 | 		rm->atomic.op_notifier->n_status = RDS_RDMA_SUCCESS;
   81 | 	}
   82 | 
   83 | 	rm->atomic.op_rkey = rds_rdma_cookie_key(args->cookie);
   84 | 	rm->atomic.op_remote_addr = args->remote_addr + rds_rdma_cookie_offset(args->cookie);
   85 | 
   86 | 	return ret;
   87 | err:
   88 | 	if (page)
   89 | 		put_page(page);
   90 | 	kfree(rm->atomic.op_notifier);
   91 | 
   92 | 	return ret;
   93 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=97`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > Replaced the reachable BUG() in the default case with a clean -EINVAL return, and made the error path reset op_active and op_notifier so a failed cmsg does not leave the message in a partially initialized state that could later be freed or reused incorrectly. Also normalized the rds_pin_pages failure return value.

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=93`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > The default case previously called BUG(), which lets an attacker trigger a kernel panic by supplying an unexpected cmsg type. It now returns -EINVAL instead, rejecting the invalid message without crashing.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=94`
- 参考修复：不可用（reference fixed function is unavailable for this unit）
- 模型说明：
  > Replaced the BUG() call in the default switch case with a proper -EINVAL return, preventing a kernel panic from an unexpected cmsg_type. Also nulled op_notifier after kfree to avoid a dangling pointer.


### 选择依据

- 规则：`strategy_disagreement` — 独立集同一 idx 上至少两个可用策略给出有效检测且预测不全相同；按不同预测类别数、置信度跨度和平均置信度排序。
- 候选池：14；类别内排名：1；score=1037.500
- 评分组成：`{"distinct_term": 1000.0, "spread_term": 30.000000000000004, "mean_confidence_term": 7.5, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 分歧只描述同一记录上的预测差异，不自动归因于提示内容；如需因果解释，应结合 prompt 长度、示例和上下文覆盖率另行分析。

## C-04 配对 both_flagged（两侧均报漏洞）

- **类别**：`pair_both_flagged`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`19923:19924`

**摘要**：配对 both_flagged：pair_id=19923:19924，3/3 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=both_flagged; few-shot=both_flagged; context=both_flagged。
- 目标类别 both_flagged 的策略数：3/3。
- 两侧平均置信度 0.908，最小置信度 0.850。
- 配对两侧 idx：vulnerable=19923, fixed=19924。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=19923，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`keepalived`；CWE=`CWE-119`；CVE=`CVE-2018-19115`；filepath=`lib/html.c`；commit=`f28015671a4b04785859d1b4b1327b367b6a10e9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | tp | unused |
| few-shot | 漏洞 | 0.950 | tp | unused |
| context | 漏洞 | 0.950 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > strncat copies up to inc bytes into a 10-byte buffer without accounting for the destination size, causing a heap buffer overflow if the status code field is longer than 9 bytes; also MALLOC result is not checked and buffer is not null-terminated.
- **few-shot**（漏洞，confidence=0.950）：
  > buf_code is allocated with MALLOC(10) but is not initialized, and strncat appends up to inc bytes from the buffer. If the status code field is longer than 9 bytes, or the uninitialized buffer lacks a NUL, strncat writes past the 10-byte allocation, causing a heap overflow.
- **context**（漏洞，confidence=0.950）：
  > buf_code is allocated with MALLOC(10) but never initialized and strncat appends up to inc bytes from the buffer without bounding to the 9-byte capacity, causing a heap buffer overflow and reading uninitialized memory; also no NULL check on MALLOC.

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

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=25`
- 参考修复：idx=19924；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.341
- 模型说明：
  > The original code used strncat into a 10-byte buffer without bounding the copied length, allowing a stack/heap overflow. The fix limits the copied status-code length to 9 bytes, null-terminates the buffer, and checks the allocation result.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=34`
- 参考修复：idx=19924；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.080
- 模型说明：
  > The original used strncat on an uninitialized MALLOC buffer, which reads uninitialized memory and can overflow the 10-byte allocation (strncat appends up to inc chars plus a NUL). The fix bounds the copy to 9 bytes, uses memcpy into the buffer, and explicitly NUL-terminates, preventing both uninitialized reads and heap overflow while preserving the status-code extraction behavior.


### 修复侧（idx=19924，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`keepalived`；CWE=`CWE-119`；CVE=`CVE-2018-19115`；filepath=`lib/html.c`；commit=`f28015671a4b04785859d1b4b1327b367b6a10e9`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.850 | fp | unused |
| few-shot | 漏洞 | 0.950 | fp | unused |
| context | 漏洞 | 0.850 | fp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.850）：
  > After the scan loop, buffer++ can move past end when no space/CR is found, and the subsequent buffer+3/end and *buffer dereferences can read out of bounds. The bounds check also uses >= which rejects valid cases and the pointer arithmetic can overflow.
- **few-shot**（漏洞，confidence=0.950）：
  > After the scan loop, buffer++ can move past end when no space or CR is found, and the subsequent buffer+3/end and *buffer reads can go out of bounds. The bounds check also uses >= incorrectly, and strtoul's end is compared against buffer+3 without ensuring it stays within the original buffer.
- **context**（漏洞，confidence=0.850）：
  > The loop can advance buffer to end (or past the last '\r'), then buffer++ moves it beyond end; subsequent reads like *buffer and buffer[3] can read out of bounds. Also strtoul's end pointer is reused, and the bounds check buffer+3>=end is off-by-one, allowing reads past the buffer.

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
- 候选池：56；类别内排名：1；score=1107.833
- 评分组成：`{"consensus_term": 1000.0, "mean_confidence_term": 90.83333333333333, "min_confidence_term": 17.0, "reverse_confidence_bonus": 0.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；both_flagged 说明模型没有利用修复差异。

## C-05 配对 both_clean（两侧均判安全）

- **类别**：`pair_both_clean`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`25144:25145`

**摘要**：配对 both_clean：pair_id=25144:25145，3/3 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=both_clean; few-shot=both_clean; context=both_clean。
- 目标类别 both_clean 的策略数：3/3。
- 两侧平均置信度 0.947，最小置信度 0.900。
- 配对两侧 idx：vulnerable=25144, fixed=25145。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=25144，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-264`；CVE=`CVE-2016-2496`；filepath=`services/inputflinger/InputWindow.cpp`；commit=`03a53d1c7765eeb3af0bc34c3dff02ada1953fbf`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | fn | unused |
| few-shot | 非漏洞 | 0.990 | fn | unused |
| context | 非漏洞 | 0.900 | fn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > Simple bounds check with no memory access, arithmetic overflow, or untrusted pointer use; no security vulnerability.
- **few-shot**（非漏洞，confidence=0.990）：
  > The function only performs integer comparisons against frame bounds and returns a boolean. It has no memory access, arithmetic overflow, or other security-relevant operation.
- **context**（非漏洞，confidence=0.900）：
  > Simple bounds check comparing coordinates against frame edges; no memory access, arithmetic overflow, or unsafe operations. No security vulnerability evident.

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

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=False`, `fixed_line_count=4`
- 参考修复：idx=25145；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.000
- 模型说明：
  > The function already performs a straightforward bounds check with no memory-unsafe operations, so no security defect is present and the behavior is preserved unchanged.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=False`, `fixed_line_count=4`
- 参考修复：idx=25145；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.000
- 模型说明：
  > The function performs only bounded integer comparisons with no memory access, pointer arithmetic, or untrusted indexing, so there is no exploitable security defect in the supplied code. The implementation is preserved unchanged to maintain the intended behavior and signature.


### 修复侧（idx=25145，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-264`；CVE=`CVE-2016-2496`；filepath=`services/inputflinger/InputWindow.cpp`；commit=`03a53d1c7765eeb3af0bc34c3dff02ada1953fbf`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.950 | tn | unused |
| few-shot | 非漏洞 | 0.990 | tn | unused |
| context | 非漏洞 | 0.900 | tn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.950）：
  > Simple bounds check comparing integers against frame edges; no memory access, arithmetic overflow, or pointer issues. No security vulnerability.
- **few-shot**（非漏洞，confidence=0.990）：
  > A pure bounds check comparing integer coordinates against frame edges; no memory access, arithmetic overflow, or unsafe operations.
- **context**（非漏洞，confidence=0.900）：
  > Simple bounds check comparing coordinates against frame edges; no memory access, arithmetic overflow, or unsafe operations.

**代码摘录**

```cpp
    1 | bool InputWindowInfo::frameContainsPoint(int32_t x, int32_t y) const {
    2 |    return x >= frameLeft && x < frameRight
    3 |            && y >= frameTop && y < frameBottom;
    4 | }
```


### 选择依据

- 规则：`pair_both_clean` — 配对两侧均被同一策略判为非漏洞；排序规则同 both_flagged。
- 候选池：119；类别内排名：1；score=1110.047
- 评分组成：`{"consensus_term": 1000.0, "mean_confidence_term": 94.66666666666667, "min_confidence_term": 18.0, "reverse_confidence_bonus": 0.0, "length_penalty": 2.62}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；both_clean 说明模型漏掉了该对中的漏洞侧。

## C-06 配对判反（漏洞侧判安全、修复侧判漏洞）

- **类别**：`pair_reversed`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`15922:15928`

**摘要**：配对 reversed：pair_id=15922:15928，1/3 个可用策略给出该联合类别。

**关键事实**

- 各策略联合类别：direct=both_flagged; few-shot=reversed; context=both_flagged。
- 目标类别 reversed 的策略数：1/3。
- 两侧平均置信度 0.850，最小置信度 0.850。
- 配对两侧 idx：vulnerable=15922, fixed=15928。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=15922，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`pjproject`；CWE=`CWE-120`；CVE=`CVE-2022-39244`；filepath=`pjmedia/src/pjmedia/sdp.c`；commit=`c4d34984ec92b3d5252a7d5cddd85a1d3a8001ae`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.600 | tp | unused |
| few-shot | 非漏洞 | 0.850 | fn | unused |
| context | 漏洞 | 0.750 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.600）：
  > The function reads *(scanner->curptr+1) without verifying that curptr+1 is within the scanned buffer, and pj_scan_get_char is called without checking for end-of-input, so a truncated 'm' line (e.g. 'm' at end of buffer) can cause an out-of-bounds read. The port/port_count values are also cast/truncated without range validation.
- **few-shot**（非漏洞，confidence=0.850）：
  > The format list is bounded by PJMEDIA_MAX_SDP_FMT before writing to fmt[], and the scanner helpers handle token extraction. No obvious out-of-bounds write or unchecked indexing is present.
- **context**（漏洞，confidence=0.750）：
  > parse_media dereferences *(scanner->curptr+1) without checking that curptr+1 is within the scanner buffer, and later reads *scanner->curptr without an EOF check; a truncated or malformed SDP line ending at the buffer boundary can cause an out-of-bounds read. The format loop also relies on curptr being valid. These unchecked pointer dereferences on untrusted input are a security concern.

**代码摘录**

```c
    1 | static void parse_media(pj_scanner *scanner, pjmedia_sdp_media *med,
    2 | 			volatile parse_context *ctx)
    3 | {
    4 |     pj_str_t str;
    5 | 
    6 |     ctx->last_error = PJMEDIA_SDP_EINMEDIA;
    7 | 
    8 |     /* check the equal sign */
    9 |     if (*(scanner->curptr+1) != '=') {
   10 | 	on_scanner_error(scanner);
   11 | 	return;
   12 |     }
   13 | 
   14 |     /* m= */
   15 |     pj_scan_advance_n(scanner, 2, SKIP_WS);
   16 | 
   17 |     /* type */
   18 |     pj_scan_get_until_ch(scanner, ' ', &med->desc.media);
   19 |     pj_scan_get_char(scanner);
   20 | 
   21 |     /* port */
   22 |     pj_scan_get(scanner, &cs_token, &str);
   23 |     med->desc.port = (unsigned short)pj_strtoul(&str);
   24 |     if (*scanner->curptr == '/') {
   25 | 	/* port count */
   26 | 	pj_scan_get_char(scanner);
   27 | 	pj_scan_get(scanner, &cs_token, &str);
   28 | 	med->desc.port_count = pj_strtoul(&str);
   29 | 
   30 |     } else {
   31 | 	med->desc.port_count = 0;
   32 |     }
   33 | 
   34 |     if (pj_scan_get_char(scanner) != ' ') {
   35 | 	PJ_THROW(SYNTAX_ERROR);
   36 |     }
   37 | 
   38 |     /* transport */
   39 |     pj_scan_get_until_chr(scanner, " \t\r\n", &med->desc.transport);
   40 | 
   41 |     /* format list */
   42 |     med->desc.fmt_count = 0;
   43 |     while (*scanner->curptr == ' ') {
   44 | 	pj_str_t fmt;
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=False`, `fixed_line_count=64`
- 参考修复：idx=15928；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.909
- 模型说明：
  > The function is unchanged because the supplied code already bounds the format list with PJMEDIA_MAX_SDP_FMT and uses the scanner's safe tokenization routines; no security defect is present in the provided source.

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=False`, `fixed_line_count=64`
- 参考修复：idx=15928；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.909
- 模型说明：
  > The function is unchanged from the supplied source; it already bounds the format list with PJMEDIA_MAX_SDP_FMT and uses the scanner's checked accessors, so no additional security defect is present in this function.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=64`
- 参考修复：idx=15928；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.924
- 模型说明：
  > Added an end-of-input check (pj_scan_is_eof) before dereferencing scanner->curptr+1, preventing an out-of-bounds read when the scanner is at or near the end of the buffer. The rest of the parsing logic is unchanged.


### 修复侧（idx=15928，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`pjproject`；CWE=`CWE-120`；CVE=`CVE-2022-39244`；filepath=`pjmedia/src/pjmedia/sdp.c`；commit=`c4d34984ec92b3d5252a7d5cddd85a1d3a8001ae`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.700 | fp | unused |
| few-shot | 漏洞 | 0.850 | fp | unused |
| context | 漏洞 | 0.800 | fp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.700）：
  > In the format-list loop, after pj_scan_get_char(scanner) consumes a space, the code dereferences *scanner->curptr without checking scanner->curptr < scanner->end, so a line ending in a space at EOF can read past the buffer. The loop condition only guards the top of the loop, not this post-advance dereference.
- **few-shot**（漏洞，confidence=0.850）：
  > After pj_scan_get_char(scanner) for the space, the code dereferences *scanner->curptr without checking for EOF, so a truncated m= line can read past the buffer end.
- **context**（漏洞，confidence=0.800）：
  > In the format-list loop, after pj_scan_get_char(scanner) consumes a space, the code dereferences *scanner->curptr without checking scanner->curptr < scanner->end, so a line ending in a space at EOF causes an out-of-bounds read. The loop condition only guards the top of the loop, not after advancing.

**代码摘录**

```c
    1 | static void parse_media(pj_scanner *scanner, pjmedia_sdp_media *med,
    2 | 			volatile parse_context *ctx)
    3 | {
    4 |     pj_str_t str;
    5 | 
    6 |     ctx->last_error = PJMEDIA_SDP_EINMEDIA;
    7 | 
    8 |     /* check the equal sign */
    9 |     if (scanner->curptr+1 >= scanner->end || *(scanner->curptr+1) != '=') {
   10 | 	on_scanner_error(scanner);
   11 | 	return;
   12 |     }
   13 | 
   14 |     /* m= */
   15 |     pj_scan_advance_n(scanner, 2, SKIP_WS);
   16 | 
   17 |     /* type */
   18 |     pj_scan_get_until_ch(scanner, ' ', &med->desc.media);
   19 |     pj_scan_get_char(scanner);
   20 | 
   21 |     /* port */
   22 |     pj_scan_get(scanner, &cs_token, &str);
   23 |     med->desc.port = (unsigned short)pj_strtoul(&str);
   24 |     if (pj_scan_is_eof(scanner)) {
   25 |         on_scanner_error(scanner);
   26 |         return;
   27 |     }
   28 |     if (*scanner->curptr == '/') {
   29 | 	/* port count */
   30 | 	pj_scan_get_char(scanner);
   31 | 	pj_scan_get(scanner, &cs_token, &str);
   32 | 	med->desc.port_count = pj_strtoul(&str);
   33 | 
   34 |     } else {
   35 | 	med->desc.port_count = 0;
   36 |     }
   37 | 
   38 |     if (pj_scan_get_char(scanner) != ' ') {
   39 | 	on_scanner_error(scanner);
   40 |     }
   41 | 
   42 |     /* transport */
   43 |     pj_scan_get_until_chr(scanner, " \t\r\n", &med->desc.transport);
   44 | 
   45 |     /* format list */
```


### 选择依据

- 规则：`pair_reversed` — 漏洞侧被判非漏洞且修复侧被判漏洞；排序规则同 both_flagged，并优先修复侧置信度高于漏洞侧的情形。
- 候选池：5；类别内排名：1；score=435.333
- 评分组成：`{"consensus_term": 333.3333333333333, "mean_confidence_term": 85.0, "min_confidence_term": 17.0, "reverse_confidence_bonus": 0.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 配对两侧来自同一 commit；判反说明模型方向与参考修复相反。

## C-07 修复 schema 无效

- **类别**：`repair_schema_invalid`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`10480:10481`
- **聚焦侧**：`vulnerable`

**摘要**：修复 schema 无效：10480:10481 的 direct 输出未通过校验（schema_keys_mismatch）。

**关键事实**

- 修复记录策略：direct；状态：invalid；schema_valid=false。
- 校验错误：repair JSON keys mismatch (missing=['explanation'], extra=[])。
- 该错误在所选运行的无效修复记录中出现 93 次；原始模型响应长度 4391 字符。
- 配对两侧 idx：vulnerable=10480, fixed=10481。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=10480，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`radare2`；CWE=`CWE-119`；CVE=`CVE-2017-15385`；filepath=`libr/bin/format/elf/elf.c`；commit=`21a6f570ba33fa9f52f1bba87f07acc4e8c178f4`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | tp | unused |
| few-shot | 漏洞 | 0.950 | tp | unused |
| context | 漏洞 | 0.900 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > The function reads Verdef/Verdaux structures from the file into a heap buffer sized shdr->sh_size, but bounds checks compare against `end` using potentially overflowing pointer arithmetic (vstart + sizeof(...) > end) and the loop condition `(char*)defs + i < end` can be bypassed via integer overflow of i from vd_next. Also aux.vda_name is checked with `>` instead of `>=` against dynstr_size, allowing an out-of-bounds read at index == dynstr_size when passed to sdb_set. These permit out-of-bounds reads/writes on malformed ELF input.
- **few-shot**（漏洞，confidence=0.950）：
  > The bounds checks are wrong. vstart is compared against end, but vstart is a pointer into the defs buffer, so the check does not stop reads past the buffer. The vda_name check uses > dynstr_size instead of >=, so an index equal to dynstr_size reads one byte past the dynstr buffer. The loop also advances i by vd_next without checking that i stays within sh_size.
- **context**（漏洞，confidence=0.900）：
  > The function reads verdef/verdaux structures from the file into a heap buffer sized shdr->sh_size, but bounds checks compare against `end` using vstart offsets that can be manipulated; more critically, `aux.vda_name > bin->dynstr_size` allows vda_name == dynstr_size, causing an out-of-bounds read of bin->dynstr[aux.vda_name] (off-by-one). Also the initial `shdr->sh_link > bin->ehdr.e_shnum` check permits sh_link == e_shnum, indexing bin->shdr out of bounds. These are memory-safety issues a maintainer should fix.

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
| few-shot | 漏洞 | 0.950 | fp | unused |
| context | 漏洞 | 0.900 | fp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > Multiple out-of-bounds issues: sh_link check uses > instead of >= allowing index == e_shnum; aux.vda_name compared with > dynstr_size (off-by-one) then used to index dynstr; vstart bounds checks use pointer arithmetic that can overflow; and the loop reads Verdef fields from a calloc'd buffer without validating sh_offset+i against file size. These allow OOB reads/writes on malformed ELF input.
- **few-shot**（漏洞，confidence=0.950）：
  > The bounds checks are wrong. vstart is compared against end, but vstart is derived from defs and can point past the allocation. The check vstart + sizeof(Verdaux) > end can also overflow. The dynstr index check uses > instead of >=, so an index equal to dynstr_size reads one byte past the buffer. The loop reads vd_aux and vd_next from untrusted data and advances i without validating it against sh_size.
- **context**（漏洞，confidence=0.900）：
  > The function reads Verdef/Verdaux structures from the file into a heap buffer sized shdr->sh_size, but bounds checks compare against 'end' using potentially overflowing pointer arithmetic (vstart + sizeof) and the loop condition uses i which can be advanced by attacker-controlled vd_next; also aux.vda_name is checked with '>' instead of '>=' against dynstr_size, allowing an out-of-bounds read at &bin->dynstr[aux.vda_name] when equal to size. These permit OOB reads/writes on malformed ELF input.

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
- 候选池：74；类别内排名：1；score=9407.330
- 评分组成：`{"error_frequency_term": 9300.0, "content_term": 100.0, "reference_bonus": 10.0, "length_penalty": 2.67}`
- 去重：`reused_unit=False`

### 备注

- Schema-invalid output is a format/engineering failure, not a repair-quality label.
- schema 无效是工程/格式失败，不能与“修复错误”或“修复正确”混为一谈。

## C-08 修复完整且不同，但参考不匹配

- **类别**：`repair_complete_reference_mismatch`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`25161:25163`
- **聚焦侧**：`vulnerable`

**摘要**：修复完整且不同但参考不匹配：pair_id=25161:25163，与参考修复的行级相似度 0.605，差异行数 47。

**关键事实**

- 修复策略：context；complete_function=true；changed_from_input=true。
- 与参考修复的规范化文本不相等；行级相似度 0.605，差异行数 47。
- 参考修复 idx：25163。
- 配对两侧 idx：vulnerable=25161, fixed=25163。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=25161，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-20`；CVE=`CVE-2016-2487`；filepath=`media/libstagefright/codecs/avcdec/SoftAVCDec.cpp`；commit=`918eeaa29d99d257282fafec931b4bda0e3bae12`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.600 | tp | unused |
| few-shot | 漏洞 | 0.850 | tp | unused |
| context | 漏洞 | 0.600 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.600）：
  > Output buffer pointers are computed from outputBufferWidth()*outputBufferHeight() without validating that the actual outHeader buffer is large enough, and pBuf may be NULL (mFlushOutBuffer) or too small, leading to out-of-bounds writes during decode. Also inHeader->pBuffer+nOffset/nFilledLen are not bounds-checked.
- **few-shot**（漏洞，confidence=0.850）：
  > The output buffer pointers are computed from outputBufferWidth()*outputBufferHeight() without validating that the actual outHeader buffer is large enough, so a mismatched or undersized buffer leads to out-of-bounds writes by the decoder.
- **context**（漏洞，confidence=0.600）：
  > Output buffer pointers are computed from outputBufferWidth()*outputBufferHeight() without validating that the actual outHeader buffer is large enough, and pBuf may be NULL (mFlushOutBuffer) or too small, leading to out-of-bounds writes by the decoder.

**代码摘录**

```cpp
    1 | void SoftAVC::setDecodeArgs(
    2 |          ivd_video_decode_ip_t *ps_dec_ip,
    3 |          ivd_video_decode_op_t *ps_dec_op,
    4 |          OMX_BUFFERHEADERTYPE *inHeader,
    5 |         OMX_BUFFERHEADERTYPE *outHeader,
    6 | 
    7 |          size_t timeStampIx) {
    8 |      size_t sizeY = outputBufferWidth() * outputBufferHeight();
    9 |      size_t sizeUV;
   10 |     uint8_t *pBuf;
   11 | 
   12 |      ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
   13 |      ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
   14 | 
   15 |     ps_dec_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
   16 | 
   17 |  /* When in flush and after EOS with zero byte input,
   18 |      * inHeader is set to zero. Hence check for non-null */
   19 |  if (inHeader) {
   20 |         ps_dec_ip->u4_ts = timeStampIx;
   21 |         ps_dec_ip->pv_stream_buffer =
   22 |             inHeader->pBuffer + inHeader->nOffset;
   23 |         ps_dec_ip->u4_num_Bytes = inHeader->nFilledLen;
   24 |  } else {
   25 |         ps_dec_ip->u4_ts = 0;
   26 |         ps_dec_ip->pv_stream_buffer = NULL;
   27 | 
   28 |          ps_dec_ip->u4_num_Bytes = 0;
   29 |      }
   30 | 
   31 |     if (outHeader) {
   32 |         pBuf = outHeader->pBuffer;
   33 |     } else {
   34 |         pBuf = mFlushOutBuffer;
   35 |     }
   36 |      sizeUV = sizeY / 4;
   37 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
   38 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
   39 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;
   40 | 
   41 |      ps_dec_ip->s_out_buffer.pu1_bufs[0] = pBuf;
   42 |      ps_dec_ip->s_out_buffer.pu1_bufs[1] = pBuf + sizeY;
   43 |      ps_dec_ip->s_out_buffer.pu1_bufs[2] = pBuf + sizeY + sizeUV;
   44 |      ps_dec_ip->s_out_buffer.u4_num_bufs = 3;
   45 |     return;
```

**修复记录**

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=66`
- 参考修复：idx=25163；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.605
- 模型说明：
  > The original code computed plane pointers and sizes from outputBufferWidth()*outputBufferHeight() without verifying that the destination buffer (outHeader->pBuffer or mFlushOutBuffer) is large enough, allowing out-of-bounds reads/writes. The fix validates the buffer capacity (nAllocLen for outHeader, computed size for the flush buffer) against the required Y+UV+UV layout using overflow-safe subtraction checks, and returns an empty output buffer configuration if the buffer is too small or null.
- 相对原函数的 diff（+24/-4 行）：

```diff
--- original_vulnerable
+++ model_fixed_function
@@ -8,7 +8,8 @@
      size_t sizeY = outputBufferWidth() * outputBufferHeight();
      size_t sizeUV;
     uint8_t *pBuf;
- 
+    size_t bufCapacity = 0;
+
      ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
      ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
 
@@ -27,17 +28,36 @@
 
          ps_dec_ip->u4_num_Bytes = 0;
      }
- 
+
     if (outHeader) {
         pBuf = outHeader->pBuffer;
+        bufCapacity = outHeader->nAllocLen;
     } else {
         pBuf = mFlushOutBuffer;
+        bufCapacity = sizeY + (sizeY / 4) * 2;
     }
-     sizeUV = sizeY / 4;
+
+    sizeUV = sizeY / 4;
+
+    /* Validate that the output buffer is large enough for the
+     * Y + U + V planes before exposing the plane pointers. */
+    if (pBuf == NULL || sizeY > bufCapacity ||
+        sizeUV > bufCapacity - sizeY ||
+        sizeUV > bufCapacity - sizeY - sizeUV) {
+        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = 0;
+        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = 0;
+        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = 0;
+        ps_dec_ip->s_out_buffer.pu1_bufs[0] = NULL;
+        ps_dec_ip->s_out_buffer.pu1_bufs[1] = NULL;
+        ps_dec_ip->s_out_buffer.pu1_bufs[2] = NULL;
+        ps_dec_ip->s_out_buffer.u4_num_bufs = 0;
+        return;
+    }
+
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;
- 
+
      ps_dec_ip->s_out_buffer.pu1_bufs[0] = pBuf;
      ps_dec_ip->s_out_buffer.pu1_bufs[1] = pBuf + sizeY;
      ps_dec_ip->s_out_buffer.pu1_bufs[2] = pBuf + sizeY + sizeUV;
```

- 相对参考修复的 diff（+17/-30 行）：

```diff
--- model_fixed_function
+++ reference_fixed
@@ -1,4 +1,5 @@
 void SoftAVC::setDecodeArgs(
+bool SoftAVC::setDecodeArgs(
          ivd_video_decode_ip_t *ps_dec_ip,
          ivd_video_decode_op_t *ps_dec_op,
          OMX_BUFFERHEADERTYPE *inHeader,
@@ -7,9 +8,7 @@
          size_t timeStampIx) {
      size_t sizeY = outputBufferWidth() * outputBufferHeight();
      size_t sizeUV;
-    uint8_t *pBuf;
-    size_t bufCapacity = 0;
-
+ 
      ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
      ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
 
@@ -28,39 +27,27 @@
 
          ps_dec_ip->u4_num_Bytes = 0;
      }
-
-    if (outHeader) {
-        pBuf = outHeader->pBuffer;
-        bufCapacity = outHeader->nAllocLen;
-    } else {
-        pBuf = mFlushOutBuffer;
-        bufCapacity = sizeY + (sizeY / 4) * 2;
-    }
-
-    sizeUV = sizeY / 4;
-
-    /* Validate that the output buffer is large enough for the
-     * Y + U + V planes before exposing the plane pointers. */
-    if (pBuf == NULL || sizeY > bufCapacity ||
-        sizeUV > bufCapacity - sizeY ||
-        sizeUV > bufCapacity - sizeY - sizeUV) {
-        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = 0;
-        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = 0;
-        ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = 0;
-        ps_dec_ip->s_out_buffer.pu1_bufs[0] = NULL;
-        ps_dec_ip->s_out_buffer.pu1_bufs[1] = NULL;
-        ps_dec_ip->s_out_buffer.pu1_bufs[2] = NULL;
-        ps_dec_ip->s_out_buffer.u4_num_bufs = 0;
-        return;
-    }
-
+ 
+     sizeUV = sizeY / 4;
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;
+ 
+    uint8_t *pBuf;
+    if (outHeader) {
+        if (outHeader->nAllocLen < sizeY + (sizeUV * 2)) {
+            android_errorWriteLog(0x534e4554, "27569635");
+            return false;
+        }
+        pBuf = outHeader->pBuffer;
+    } else {
+        // mFlushOutBuffer always has the right size.
+        pBuf = mFlushOutBuffer;
+    }
 
      ps_dec_ip->s_out_buffer.pu1_bufs[0] = pBuf;
      ps_dec_ip->s_out_buffer.pu1_bufs[1] = pBuf + sizeY;
      ps_dec_ip->s_out_buffer.pu1_bufs[2] = pBuf + sizeY + sizeUV;
      ps_dec_ip->s_out_buffer.u4_num_bufs = 3;
-    return;
+    return true;
  }
```

- 模型修复函数摘录：

```c
    1 | void SoftAVC::setDecodeArgs(
    2 |          ivd_video_decode_ip_t *ps_dec_ip,
    3 |          ivd_video_decode_op_t *ps_dec_op,
    4 |          OMX_BUFFERHEADERTYPE *inHeader,
    5 |         OMX_BUFFERHEADERTYPE *outHeader,
    6 | 
    7 |          size_t timeStampIx) {
    8 |      size_t sizeY = outputBufferWidth() * outputBufferHeight();
    9 |      size_t sizeUV;
   10 |     uint8_t *pBuf;
   11 |     size_t bufCapacity = 0;
   12 | 
   13 |      ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
   14 |      ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
   15 | 
   16 |     ps_dec_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
   17 | 
   18 |  /* When in flush and after EOS with zero byte input,
   19 |      * inHeader is set to zero. Hence check for non-null */
   20 |  if (inHeader) {
   21 |         ps_dec_ip->u4_ts = timeStampIx;
   22 |         ps_dec_ip->pv_stream_buffer =
   23 |             inHeader->pBuffer + inHeader->nOffset;
   24 |         ps_dec_ip->u4_num_Bytes = inHeader->nFilledLen;
   25 |  } else {
   26 |         ps_dec_ip->u4_ts = 0;
   27 |         ps_dec_ip->pv_stream_buffer = NULL;
   28 | 
   29 |          ps_dec_ip->u4_num_Bytes = 0;
   30 |      }
   31 | 
   32 |     if (outHeader) {
   33 |         pBuf = outHeader->pBuffer;
   34 |         bufCapacity = outHeader->nAllocLen;
   35 |     } else {
   36 |         pBuf = mFlushOutBuffer;
   37 |         bufCapacity = sizeY + (sizeY / 4) * 2;
   38 |     }
   39 | 
   40 |     sizeUV = sizeY / 4;
   41 | 
   42 |     /* Validate that the output buffer is large enough for the
   43 |      * Y + U + V planes before exposing the plane pointers. */
   44 |     if (pBuf == NULL || sizeY > bufCapacity ||
   45 |         sizeUV > bufCapacity - sizeY ||
```


### 修复侧（idx=25163，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`Android`；CWE=`CWE-20`；CVE=`CVE-2016-2487`；filepath=`media/libstagefright/codecs/avcdec/SoftAVCDec.cpp`；commit=`918eeaa29d99d257282fafec931b4bda0e3bae12`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.700 | tn | unused |
| few-shot | 非漏洞 | 0.850 | tn | unused |
| context | 非漏洞 | 0.700 | tn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.700）：
  > The function validates that outHeader->nAllocLen is at least sizeY + 2*sizeUV before using the buffer, and falls back to a correctly-sized internal buffer when outHeader is null. Buffer offsets are computed consistently with the validated total size, so no obvious out-of-bounds write is present.
- **few-shot**（非漏洞，confidence=0.850）：
  > The output buffer size is validated against the required Y+UV allocation before pointers are set, and the input buffer is only referenced, not copied. No unchecked write or arithmetic overflow is evident in this function.
- **context**（非漏洞，confidence=0.700）：
  > The function validates outHeader->nAllocLen against the required sizeY + 2*sizeUV before using the buffer, and falls back to a correctly-sized mFlushOutBuffer when outHeader is null. Integer overflow in sizeY computation is theoretically possible but outputBufferWidth/Height are decoder-controlled dimensions, and the allocation check guards the write path.

**代码摘录**

```cpp
    1 | void SoftAVC::setDecodeArgs(
    2 | bool SoftAVC::setDecodeArgs(
    3 |          ivd_video_decode_ip_t *ps_dec_ip,
    4 |          ivd_video_decode_op_t *ps_dec_op,
    5 |          OMX_BUFFERHEADERTYPE *inHeader,
    6 |         OMX_BUFFERHEADERTYPE *outHeader,
    7 | 
    8 |          size_t timeStampIx) {
    9 |      size_t sizeY = outputBufferWidth() * outputBufferHeight();
   10 |      size_t sizeUV;
   11 | 
   12 |      ps_dec_ip->u4_size = sizeof(ivd_video_decode_ip_t);
   13 |      ps_dec_op->u4_size = sizeof(ivd_video_decode_op_t);
   14 | 
   15 |     ps_dec_ip->e_cmd = IVD_CMD_VIDEO_DECODE;
   16 | 
   17 |  /* When in flush and after EOS with zero byte input,
   18 |      * inHeader is set to zero. Hence check for non-null */
   19 |  if (inHeader) {
   20 |         ps_dec_ip->u4_ts = timeStampIx;
   21 |         ps_dec_ip->pv_stream_buffer =
   22 |             inHeader->pBuffer + inHeader->nOffset;
   23 |         ps_dec_ip->u4_num_Bytes = inHeader->nFilledLen;
   24 |  } else {
   25 |         ps_dec_ip->u4_ts = 0;
   26 |         ps_dec_ip->pv_stream_buffer = NULL;
   27 | 
   28 |          ps_dec_ip->u4_num_Bytes = 0;
   29 |      }
   30 | 
   31 |      sizeUV = sizeY / 4;
   32 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[0] = sizeY;
   33 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[1] = sizeUV;
   34 |      ps_dec_ip->s_out_buffer.u4_min_out_buf_size[2] = sizeUV;
   35 | 
   36 |     uint8_t *pBuf;
   37 |     if (outHeader) {
   38 |         if (outHeader->nAllocLen < sizeY + (sizeUV * 2)) {
   39 |             android_errorWriteLog(0x534e4554, "27569635");
   40 |             return false;
   41 |         }
   42 |         pBuf = outHeader->pBuffer;
   43 |     } else {
   44 |         // mFlushOutBuffer always has the right size.
   45 |         pBuf = mFlushOutBuffer;
```


### 选择依据

- 规则：`repair_complete_reference_mismatch` — 配对修复记录 schema 有效、complete_function=true、changed_from_input=true，且规范化文本与参考修复不相等；按文本差异度、改动行数和结构校验排序。
- 候选池：304；类别内排名：1；score=228.992
- 评分组成：`{"similarity_target": 0.6, "similarity_distance": 0.005042016806722671, "similarity_term": 198.99159663865547, "diff_line_term": 20.0, "structural_bonus": 10.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- Reference mismatch is a text comparison, not proof that the repair is incorrect.
- 参考不匹配是规范化文本比较的结果，不是修复错误或安全等价性的证明；完整且不同也可能是另一种有效修复。

## C-09 context 高风险判定

- **类别**：`context_high_risk`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`679:680`
- **聚焦侧**：`vulnerable`

**摘要**：context 高风险判定：679:680 的 vulnerable 侧，is_vulnerable=True，置信度 0.900，标签=漏洞，上下文非空=True。

**关键事实**

- context 预测：is_vulnerable=True，confidence=0.900。
- 标签：漏洞；预测正确。
- context.used=true；nonempty=True；section_item_counts={"External Function": 1, "Type Execution Declaration": 2}。
- 配对两侧 idx：vulnerable=679, fixed=680。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=679，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`linux`；CWE=`CWE-20`；CVE=`CVE-2013-1828`；filepath=`net/sctp/socket.c`；commit=`726bc6b092da4c093eb74d13c07184b18c1af0f1`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 漏洞 | 0.900 | tp | unused |
| few-shot | 漏洞 | 0.950 | tp | unused |
| context | 漏洞 | 0.900 | tp | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（漏洞，confidence=0.900）：
  > copy_from_user(&sas, optval, len) copies len bytes into the fixed-size stack struct sas without bounding len to sizeof(sas) first; a user-supplied len larger than sizeof(struct sctp_assoc_stats) causes a stack buffer overflow. The min_t clamp happens only after the copy.
- **few-shot**（漏洞，confidence=0.950）：
  > The user-supplied len is passed to copy_from_user into the fixed-size stack struct sas without being capped to sizeof(sas), so a large len overflows the stack buffer.
- **context**（漏洞，confidence=0.900）：
  > copy_from_user(&sas, optval, len) copies len bytes into a fixed-size stack struct sas without bounding len to sizeof(sas) first; a user-supplied len larger than sizeof(struct sctp_assoc_stats) causes a stack buffer overflow. The min_t clamp happens only after the copy.

**代码摘录**

```c
    1 | static int sctp_getsockopt_assoc_stats(struct sock *sk, int len,
    2 | 				       char __user *optval,
    3 | 				       int __user *optlen)
    4 | {
    5 | 	struct sctp_assoc_stats sas;
    6 | 	struct sctp_association *asoc = NULL;
    7 | 
    8 | 	/* User must provide at least the assoc id */
    9 | 	if (len < sizeof(sctp_assoc_t))
   10 | 		return -EINVAL;
   11 | 
   12 | 	if (copy_from_user(&sas, optval, len))
   13 | 		return -EFAULT;
   14 | 
   15 | 	asoc = sctp_id2assoc(sk, sas.sas_assoc_id);
   16 | 	if (!asoc)
   17 | 		return -EINVAL;
   18 | 
   19 | 	sas.sas_rtxchunks = asoc->stats.rtxchunks;
   20 | 	sas.sas_gapcnt = asoc->stats.gapcnt;
   21 | 	sas.sas_outofseqtsns = asoc->stats.outofseqtsns;
   22 | 	sas.sas_osacks = asoc->stats.osacks;
   23 | 	sas.sas_isacks = asoc->stats.isacks;
   24 | 	sas.sas_octrlchunks = asoc->stats.octrlchunks;
   25 | 	sas.sas_ictrlchunks = asoc->stats.ictrlchunks;
   26 | 	sas.sas_oodchunks = asoc->stats.oodchunks;
   27 | 	sas.sas_iodchunks = asoc->stats.iodchunks;
   28 | 	sas.sas_ouodchunks = asoc->stats.ouodchunks;
   29 | 	sas.sas_iuodchunks = asoc->stats.iuodchunks;
   30 | 	sas.sas_idupchunks = asoc->stats.idupchunks;
   31 | 	sas.sas_opackets = asoc->stats.opackets;
   32 | 	sas.sas_ipackets = asoc->stats.ipackets;
   33 | 
   34 | 	/* New high max rto observed, will return 0 if not a single
   35 | 	 * RTO update took place. obs_rto_ipaddr will be bogus
   36 | 	 * in such a case
   37 | 	 */
   38 | 	sas.sas_maxrto = asoc->stats.max_obs_rto;
   39 | 	memcpy(&sas.sas_obs_rto_ipaddr, &asoc->stats.obs_rto_ipaddr,
   40 | 		sizeof(struct sockaddr_storage));
   41 | 
   42 | 	/* Mark beginning of a new observation period */
   43 | 	asoc->stats.max_obs_rto = asoc->rto_min;
   44 | 
   45 | 	/* Allow the struct to grow and fill in as much as possible */
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=58`
- 参考修复：idx=680；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.983
- 模型说明：
  > The original code copied `len` bytes from userspace into the fixed-size stack struct `sas` before clamping `len`, allowing a stack buffer overflow when the user passes a length larger than sizeof(sas). The fix clamps `len` to sizeof(sas) before the copy_from_user, so only the struct's capacity is ever written, while preserving the intended behavior of returning at most sizeof(sas) bytes.

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=58`
- 参考修复：idx=680；exact_match=`True`；whitespace_collapsed_match=`True`；line_similarity=1.000
- 模型说明：
  > The original copied len bytes from userspace into the fixed-size stack struct sas before clamping len, allowing a stack buffer overflow. The fix clamps len to sizeof(sas) before copy_from_user, so only the struct's own size is ever copied in or out.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=63`
- 参考修复：idx=680；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.942
- 模型说明：
  > The original code copied `len` bytes from user space into the fixed-size stack struct `sas` before clamping `len`, allowing a stack buffer overflow when the caller supplies a length larger than sizeof(sas). The fix clamps `len` to sizeof(sas) prior to copy_from_user, preserving the intended behavior of accepting at least an assoc id and returning as much of the struct as fits.


### 修复侧（idx=680，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`linux`；CWE=`CWE-20`；CVE=`CVE-2013-1828`；filepath=`net/sctp/socket.c`；commit=`726bc6b092da4c093eb74d13c07184b18c1af0f1`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.800 | tn | unused |
| few-shot | 非漏洞 | 0.850 | tn | unused |
| context | 非漏洞 | 0.800 | tn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.800）：
  > The function bounds len to sizeof(sas) before copy_from_user and copy_to_user, so no stack overflow or info leak beyond the struct occurs. The struct is fully initialized by copy_from_user of at least sizeof(sctp_assoc_t) and then fields are overwritten; remaining padding could theoretically leak but the copy length is capped to the struct size and the assoc id is validated. No clear exploitable vulnerability.
- **few-shot**（非漏洞，confidence=0.850）：
  > The length is clamped to sizeof(sas) before copy_from_user and copy_to_user, and the minimum size is checked. The stack struct is fully initialized by the copy and the field assignments, so no uninitialized stack data is leaked.
- **context**（非漏洞，confidence=0.800）：
  > The function validates len >= sizeof(sctp_assoc_t), clamps len to sizeof(sas) before copy_from_user, and uses the same clamped len for copy_to_user, so no stack over-read/over-write occurs. sctp_id2assoc result is checked for NULL. No clear memory-safety issue.

**代码摘录**

```c
    1 | static int sctp_getsockopt_assoc_stats(struct sock *sk, int len,
    2 | 				       char __user *optval,
    3 | 				       int __user *optlen)
    4 | {
    5 | 	struct sctp_assoc_stats sas;
    6 | 	struct sctp_association *asoc = NULL;
    7 | 
    8 | 	/* User must provide at least the assoc id */
    9 | 	if (len < sizeof(sctp_assoc_t))
   10 | 		return -EINVAL;
   11 | 
   12 | 	/* Allow the struct to grow and fill in as much as possible */
   13 | 	len = min_t(size_t, len, sizeof(sas));
   14 | 
   15 | 	if (copy_from_user(&sas, optval, len))
   16 | 		return -EFAULT;
   17 | 
   18 | 	asoc = sctp_id2assoc(sk, sas.sas_assoc_id);
   19 | 	if (!asoc)
   20 | 		return -EINVAL;
   21 | 
   22 | 	sas.sas_rtxchunks = asoc->stats.rtxchunks;
   23 | 	sas.sas_gapcnt = asoc->stats.gapcnt;
   24 | 	sas.sas_outofseqtsns = asoc->stats.outofseqtsns;
   25 | 	sas.sas_osacks = asoc->stats.osacks;
   26 | 	sas.sas_isacks = asoc->stats.isacks;
   27 | 	sas.sas_octrlchunks = asoc->stats.octrlchunks;
   28 | 	sas.sas_ictrlchunks = asoc->stats.ictrlchunks;
   29 | 	sas.sas_oodchunks = asoc->stats.oodchunks;
   30 | 	sas.sas_iodchunks = asoc->stats.iodchunks;
   31 | 	sas.sas_ouodchunks = asoc->stats.ouodchunks;
   32 | 	sas.sas_iuodchunks = asoc->stats.iuodchunks;
   33 | 	sas.sas_idupchunks = asoc->stats.idupchunks;
   34 | 	sas.sas_opackets = asoc->stats.opackets;
   35 | 	sas.sas_ipackets = asoc->stats.ipackets;
   36 | 
   37 | 	/* New high max rto observed, will return 0 if not a single
   38 | 	 * RTO update took place. obs_rto_ipaddr will be bogus
   39 | 	 * in such a case
   40 | 	 */
   41 | 	sas.sas_maxrto = asoc->stats.max_obs_rto;
   42 | 	memcpy(&sas.sas_obs_rto_ipaddr, &asoc->stats.obs_rto_ipaddr,
   43 | 		sizeof(struct sockaddr_storage));
   44 | 
   45 | 	/* Mark beginning of a new observation period */
```


### 选择依据

- 规则：`context_high_risk` — context 策略有效检测且预测 is_vulnerable=true，context.used=true；按置信度、上下文非空和标签一致性排序。
- 候选池：169；类别内排名：2；score=107.000
- 评分组成：`{"confidence_term": 90.0, "context_nonempty_bonus": 10.0, "label_match_bonus": 5.0, "pair_bonus": 2.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 数据审计指出 context 是否非空与标签相关；不能把本案例直接归因于“上下文推理能力”。

## C-10 context 低风险判定

- **类别**：`context_low_risk`
- **数据集**：`pairs`
- **idx**：`—`
- **pair_id**：`16915:16937`
- **聚焦侧**：`fixed`

**摘要**：context 低风险判定：16915:16937 的 fixed 侧，is_vulnerable=False，置信度 0.900，标签=非漏洞，上下文非空=True。

**关键事实**

- context 预测：is_vulnerable=False，confidence=0.900。
- 标签：非漏洞；预测正确。
- context.used=true；nonempty=True；section_item_counts={"Function Argument": 1, "Globals": 1, "Type Execution Declaration": 1}。
- 配对两侧 idx：vulnerable=16915, fixed=16937。
- 分析元数据（project/CWE/CVE/filepath/commit）只用于本导出，从未进入模型提示。

### 漏洞侧（idx=16915，label=True）

**分析元数据（仅用于分析，未进入模型提示）**：project=`relic`；CWE=`CWE-190`；CVE=`CVE-2023-36326`；filepath=`src/fpx/relic_fpx_util.c`；commit=`34580d840469361ba9b5f001361cad659687b9ab`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.800 | fn | unused |
| few-shot | 非漏洞 | 0.900 | fn | unused |
| context | 非漏洞 | 0.900 | fn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.800）：
  > Length is validated against the exact expected size (9*RLC_FP_BYTES) before reading, and the three fp3_read_bin calls cover exactly that buffer with correct offsets; no out-of-bounds access is evident.
- **few-shot**（非漏洞，confidence=0.900）：
  > The function validates that len equals the exact expected size before reading, and the three sub-reads cover exactly that many bytes with no overflow or out-of-bounds access.
- **context**（非漏洞，confidence=0.900）：
  > The function validates that len equals 9*RLC_FP_BYTES before reading, and the subsequent reads are bounded within that length, so no out-of-bounds access occurs.

**代码摘录**

```c
    1 | void fp9_read_bin(fp9_t a, const uint8_t *bin, int len) {
    2 | 	if (len != 9 * RLC_FP_BYTES) {
    3 | 		RLC_THROW(ERR_NO_BUFFER);
    4 | 		return;
    5 | 	}
    6 | 	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
    7 | 	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
    8 | 	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
    9 | }
```

**修复记录**

#### 修复策略 `direct`

- 策略：`direct`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=13`
- 参考修复：idx=16937；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.727
- 模型说明：
  > Added a NULL check on the input buffer before dereferencing it, preventing a null-pointer dereference while preserving the original length validation and behavior.

#### 修复策略 `few-shot`

- 策略：`few-shot`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`false`；complete_and_changed=`false`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=False`, `whitespace_changed_from_input=False`, `fixed_line_count=9`
- 参考修复：idx=16937；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.889
- 模型说明：
  > The function already validates that len equals the exact expected size (9 * RLC_FP_BYTES) before reading, and each fp3_read_bin call is given the correct 3 * RLC_FP_BYTES length with in-bounds offsets. No security defect is present in the supplied code, so the function is preserved unchanged.

#### 修复策略 `context`

- 策略：`context`
- 状态：`ok`；schema_valid=`true`
- complete_function=`true`；changed_from_input=`true`；complete_and_changed=`true`
- 结构校验：`schema_valid=True`, `complete_function=True`, `balanced_delimiters=True`, `function_like_prefix=True`, `contains_markdown_fence=False`, `starts_like_diff=False`, `changed_from_input=True`, `whitespace_changed_from_input=True`, `fixed_line_count=13`
- 参考修复：idx=16937；exact_match=`False`；whitespace_collapsed_match=`False`；line_similarity=0.727
- 模型说明：
  > Added a NULL check on the input buffer before dereferencing it, preventing a null-pointer dereference while preserving the original length validation and behavior.


### 修复侧（idx=16937，label=False）

**分析元数据（仅用于分析，未进入模型提示）**：project=`relic`；CWE=`CWE-190`；CVE=`CVE-2023-36326`；filepath=`src/fpx/relic_fpx_util.c`；commit=`34580d840469361ba9b5f001361cad659687b9ab`

**策略预测**

| 策略 | 预测 | 置信度 | 判定 | 上下文 |
| --- | --- | ---: | --- | --- |
| direct | 非漏洞 | 0.850 | tn | unused |
| few-shot | 非漏洞 | 0.900 | tn | unused |
| context | 非漏洞 | 0.900 | tn | used/nonempty |

**模型 rationale（原文，已按需截断）**

- **direct**（非漏洞，confidence=0.850）：
  > The function validates that len equals exactly 9*RLC_FP_BYTES before reading, and the three fp3_read_bin calls each consume 3*RLC_FP_BYTES within bounds. No buffer overflow or unchecked access is evident.
- **few-shot**（非漏洞，confidence=0.900）：
  > The function validates that len equals exactly 9*RLC_FP_BYTES before reading, then splits the buffer into three fixed-size chunks with correct offsets. No overflow or out-of-bounds access is evident.
- **context**（非漏洞，confidence=0.900）：
  > The function validates that len equals exactly 9*RLC_FP_BYTES before reading, and all subsequent reads are bounded within that length. No buffer overflow or out-of-bounds access is present.

**代码摘录**

```c
    1 | void fp9_read_bin(fp9_t a, const uint8_t *bin, size_t len) {
    2 | 	if (len != 9 * RLC_FP_BYTES) {
    3 | 		RLC_THROW(ERR_NO_BUFFER);
    4 | 		return;
    5 | 	}
    6 | 	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
    7 | 	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
    8 | 	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
    9 | }
```


### 选择依据

- 规则：`context_low_risk` — context 策略有效检测且预测 is_vulnerable=false，context.used=true；排序规则同 context_high_risk。
- 候选池：351；类别内排名：1；score=107.000
- 评分组成：`{"confidence_term": 90.0, "context_nonempty_bonus": 10.0, "label_match_bonus": 5.0, "pair_bonus": 2.0, "length_penalty": 0.0}`
- 去重：`reused_unit=False`

### 备注

- 数据审计指出 context 是否非空与标签相关；不能把本案例直接归因于“上下文推理能力”。
