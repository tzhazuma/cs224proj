# `benchmark/examples/` — 合成 schema 样例

**这里的记录全部是手写合成 fixture，不是模型、静态工具或动态工具的实验结果。** 不得引用为性能数字。

| 目录 | 内容 |
| --- | --- |
| `run_detection/` | 1 条函数级检测记录 + manifest |
| `run_pair/` | 1 对（vulnerable/fixed）记录 + manifest |
| `run_leak/` | 1 个 Juliet case（bad/good）+ manifest |
| `make_examples.py` | 重新生成样例并计算 manifest 中的 SHA-256 |

用途：

- 验证 `benchmark/schemas/*.json` 与 `bench_validate.py`；
- 给新方法作者一个字段齐全的起点；
- 验证 `bench_metrics.py` 在 detection/pair/leak 三种 task 上的输出结构。

## 检查

```bash
wsl bash -lc 'cd /mnt/c/Users/tzh03/Downloads/cs224proj && \
for d in benchmark/examples/run_detection benchmark/examples/run_pair benchmark/examples/run_leak; do
  python3 benchmark/tools/bench_validate.py --run-dir "$d" --jsonschema || exit 1
done'
```

## 不要做的事

- 不要把 `examples/` 复制到 `results/` 后改个名字当作真实 run；
- 不要把样例里的 `example-model`/`example-tool` 写进报告；
- 不要因为样例是 1.0 就推断任何方法有效。
