import pandas as pd

# 读取数据集
df = pd.read_excel("SecVulEval.xlsx")

# 打印样本数量
print("样本总数:", len(df))

# 查看字段名称
print("\n数据字段:")
print(df.columns.tolist())

# 查看前 3 条样本
print("\n前三条数据:")
print(df.head(3).to_string(index=False))

# 查看有漏洞和无漏洞的样本数量
print("\n漏洞标签分布:")
print(df["is_vulnerable"].value_counts())
