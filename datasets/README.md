# 实验数据子集

数据源为项目根目录的 `SecVulEval.xlsx`，读取 `train` 工作表。两个 JSON 均使用 UTF-8 编码，随机种子为 `42`。

| 文件 | 数据结构 | 数量 |
| --- | --- | --- |
| `independent_200.json` | `metadata` + `samples` | 160 条有漏洞函数、40 条无漏洞函数，共 200 条 |
| `vulnerable_fixed_200_pairs.json` | `metadata` + `pairs` | 200 对漏洞／修复版本，共 400 条函数记录 |

## 抽样规则

1. 先选取 200 对有效的漏洞／修复版本，再选取独立集合的 160 条有漏洞函数和 40 条无漏洞函数。
2. 修复配对严格使用原始 `idx` 和 `fixed_func_idx`，不依赖 Excel 行位置、函数名猜测或文本相似度。每对的项目、提交、文件和函数名必须一致，标签必须分别为 `true`、`false`，函数正文必须不同。
3. 独立集合中，每个 `(project, commit_id)` 最多取一条函数，且集合内不存在已知的漏洞／修复配对。40 条无漏洞函数也不会是任何原始漏洞记录通过 `fixed_func_idx` 指向的修复版本。
4. 配对集合中，每个 `(project, commit_id)` 最多取一对。两个集合不共享原始 `idx`，也不共享 `(project, commit_id)`，合计 600 条不同的原始记录。
5. 使用局部 `random.Random(seed)` 打乱候选记录，再按上述约束选取；没有额外的项目、CWE 或代码长度配额。这里的无配对关系指数据集已标注的关系，不代表对上游完整 Git 历史作出了证明。
6. 原始数据中有 7 条 `changed_statements` 无法解析，已排除。对应 `idx` 为 `3510, 9418, 9578, 10195, 10196, 16033, 18071`。排除详情与源文件 SHA-256 均记录在 `metadata` 中。

## JSON 格式

独立集合：

```json
{
  "metadata": {"sample_count": 200, "vulnerable_count": 160, "non_vulnerable_count": 40},
  "samples": [
    {"idx": 123, "is_vulnerable": true, "func_body": "...", "fixed_func_idx": 124}
  ]
}
```

配对集合：

```json
{
  "metadata": {"pair_count": 200, "function_count": 400},
  "pairs": [
    {
      "pair_id": "123:124",
      "vulnerable": {"idx": 123, "is_vulnerable": true, "fixed_func_idx": 124, "func_body": "..."},
      "fixed": {"idx": 124, "is_vulnerable": false, "fixed_func_idx": 124, "func_body": "..."}
    }
  ]
}
```

以上仅为结构示例。实际文件保留每条记录的全部 16 个原始字段，完整保留函数源码。`changed_lines`、`changed_statements`、`cve_list`、`cwe_list` 转为 JSON 数组；空单元格为 `null`，标签为 JSON 布尔值。`context` 中含有 numpy 数组的字符串表示，因此保留原始字符串，不执行其中的表达式。`fixed_func_idx` 始终指向完整源数据的索引，不是子集内的位置。

## pap 环境与软件包

以下依赖用于运行项目根目录的 `build_datasets.py`，生成本目录的两个 JSON 数据集。本机 `pap` 环境中已验证的版本如下：

| 软件包／运行时 | 已验证版本 | 用途 |
| --- | --- | --- |
| Python | `3.12.16` | 执行抽样脚本，建议使用 Python 3.12 |
| `openpyxl` | `3.1.5` | 以只读方式读取 `SecVulEval.xlsx` |
| `et_xmlfile` | `2.0.0` | `openpyxl` 的依赖，安装 `openpyxl` 时会自动安装 |

在已有的 `pap` 环境中安装上述已验证版本：

```powershell
conda run -n pap python -m pip install openpyxl==3.1.5 et_xmlfile==2.0.0
```

若需在其他机器上新建同名环境，先执行：

```powershell
conda create -n pap python=3.12 pip
```

然后执行上面的软件包安装命令。可用以下命令检查解释器和软件包版本：

```powershell
conda run -n pap python --version
conda run -n pap python -m pip show openpyxl et_xmlfile
```

脚本使用的 `argparse`、`ast`、`hashlib`、`json`、`random`、`sys`、`collections`、`pathlib` 和 `typing` 均为 Python 标准库，随 Python 提供。此抽样脚本的完整第三方依赖为表中的 `openpyxl` 及其依赖 `et_xmlfile`；项目其他实验模块的依赖请参见根目录 `README.md`。

## 在 pap 环境中重新生成

在项目根目录执行：

```powershell
conda run -n pap python build_datasets.py --seed 42
```

本机已验证的解释器是 `C:\ProgramData\anaconda3\envs\pap\python.exe`，Python 版本为 `3.12.16`。也可直接调用：

```powershell
& 'C:\ProgramData\anaconda3\envs\pap\python.exe' .\build_datasets.py --seed 42
```

脚本只读取源工作簿，不下载数据、不调用模型。相同源文件和随机种子会生成相同内容。再次运行会覆盖输出目录中的同名 JSON；可用 `--output-dir datasets_seed_43 --seed 43` 保留其他抽样结果。可通过 `--vulnerable-count`、`--non-vulnerable-count` 和 `--pair-count` 调整数量。

## 已完成的核验

- 数量、标签、原始索引唯一性、配对方向、函数身份、代码差异以及集合间的提交隔离全部通过。
- 重新读取输出，将 600 条记录的全部 9,600 个字段与 Excel 源数据逐一比对，结果一致。
- 固定种子 `42` 可复现同样的输出；更换为 `43` 会改变抽样结果。
- 校验器能够拒绝错误配对及错误标签。
