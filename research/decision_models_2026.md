# Jev 类 decision model 调研（2026-11-23）

用途：评估 Tier B（Juliet CWE-401）能否把“微调 decision model”作为创新点 3。

## 1. Jev 是什么（TypeSafe AI）
- 发布：2026-09-15（launch post: https://typesafe.ai/blog/introducing-system-one-models-and-jev）。当前版本 `jev-1.14.0`（2026-10-14）和 `jev-1.13.0`。
- 范式（官方称 "System One model"）：输入 `state` 加上带类型的 `questions`（Choice / Score / Noul(是/否概率) / Box），**不生成文本**。一次前向就给出所有选项的概率和 confidence，用 RLCD（Reinforcement Learning for Calibrated Decisions）训练。
- API：`POST https://api.typesafe.ai/v1/systemone`，key 在 https://console.typesafe.ai/keys 申请。只按输入 token 计费，**$0.042 / Mtok**，输出免费。上下文为单请求 64k、单问题 32k。
- 官方延迟：端到端 70–500 ms。只能调 API，权重不开放，**不能微调**（Torq 的博客也确认了这一点）。
- 和代码安全相关的第三方结果：
  - Escape 博客：20 个片段中召回 9/10，但良性片段误报 5/10（FPR 50%）。
  - Torq 告警分诊实验：比多数类基线还差，对 prompt 和标题措辞非常敏感。
  - Cyber-JEV 论文：Jev 1.13 函数级 AUROC 0.743。
  - 已知弱点：答案受**选项名称**而不是选项定义左右；容易被对抗后缀翻转；倾向过度报警。

## 2. 开源的 Jev 类模型（可在 2×3090 上运行）
| 模型 | 底座 | 读出方式 | 训练 | 要点 |
|---|---|---|---|---|
| Intern-Decision-0.8B/2B/4B (internlm, Apache-2.0, arXiv 2610.22131) | Qwen3.5 | JSON 骨架中每个字段一个 `<decision>` 占位符，在占位符前一位置取候选符号 logits，做受限 softmax，再做温度校准（T=1.99） | "autoregressive masked LM" 决策微调 | 4B 在 RTX 4090 上平均 44 ms/请求（289 token，3 个字段），BF16 约 8.5 GB，max_length 8192 |
| AnyJev (Nokia, arXiv 2610.00831, github nokia-applied-research/AnyJev) | 任意因果 LM | 选项 token 受限 softmax，用 K 次轮换平均消除位置偏置，并除以无标签估计的 label prior | **不训练**（L0），也有自蒸馏的 Tacit 模型 | 支持 HF/vLLM/SGLang/llama.cpp 后端，可在 CPU 上跑 |
| Cyber-JEV (arXiv 2611.02957) | Qwen3.5-4B, LoRA r16 α32 | token 初始化的二分类头，打分为 s=ℓvuln−ℓbenign | 类别平衡 CE 加上 matched-group ranking loss（漏洞函数要排在其补丁版本和同文件函数之前，τ=1，λ=1），3 epoch，单卡 | 7,270 个真实函数上 AUROC 0.814（5 个模型集成），Jev 1.13 为 0.743；零样本 Qwen3.5-4B 只有 0.640 |
| SecJev (arXiv 2610.03073) | Kev 0.8B–9B | 单次候选打分 | 14 个安全任务 | 开放了 adapter 和代码，但不涉及内存安全 |

最相关的工作是 **"Look Here, Then Decide" (arXiv 2611.16565)**：先用廉价语法定位器找候选，再用 Intern-Decision-4B 排序，最后用 ASan 复现确认。他们单独用模型的效果很弱（AUC 0.73；在漏洞函数和它自己的补丁之间只有 0.56），价值在于排序，最终在 4,000 多个项目中确认了 187 个内存安全漏洞。该文**没有覆盖 CWE-401**。

## 3. 对本项目的含义
- Juliet 天然成对（同 family 的 bad/good），很适合 Cyber-JEV 式的 matched ranking loss。
- **风险**：前面已经发现 grep 规则“没有 free/delete 就判为泄漏”在 test140 上 macro-F1 达到 0.935。成对对比训练会进一步放大这条捷径，所以必须做：
  1. 反事实增强（在 bad 里插入不可达的 `if(staticFalse) free(p);`，标签仍为泄漏）；
  2. 困难子集评测（bad 中本身含 free 的样本：realloc、虚析构等）；
  3. decoy 扰动评测。
- 只按输入计费、延迟在毫秒级，可以把**级联**当作一条曲线来展示：decision model 先判，低置信度的再交给 DeepSeek L3/L4，横轴为升级比例，画出 F1 与延迟、成本的关系。
