# Paired family-cluster bootstrap (B=2000, seed 20261123) of macro-F1 differences on Debiased eval
# (near-LLM main-line comparisons). Run from the repo root: python3 juliet_full/analysis/near_llm_bootstrap.py
# Originally /tmp/sqf.py (2026-11-23 21:58).
import json,random,math
R='juliet_full/'
M={m['key']:m for m in json.load(open('report/final_en/generated/results_summary.json'))['methods']}
meta={}
for l in open(R+'data/build/layer1.jsonl'):
    r=json.loads(l)
    if r['set']=='eval': meta[r['unit_id']]=r['family']
units=sorted(meta)
def preds(k,L='layer1'):
    d={}
    for f in M[k]['layers'][L]['files']:
        for l in open(R+f):
            r=json.loads(l); d[r['unit_id']]=r.get('pred')
    return d
def macro(us,p):
    tp=fp=tn=fn=0
    for u in us:
        y=u.endswith('__bad'); q=p.get(u)==1
        if y and q: tp+=1
        elif y: fn+=1
        elif q: fp+=1
        else: tn+=1
    f1=lambda a,b,c: 2*a/(2*a+b+c) if a else 0
    return (f1(tp,fp,fn)+f1(tn,fn,fp))/2
fams={}
for u in units: fams.setdefault(meta[u],[]).append(u)
fl=sorted(fams)
pairs=[('lora_L1','deepseek_L1'),('lora_L3','deepseek_L3'),('lora_L1','deepseek_L2'),('lora_L1','jev_L1'),('lora_L3','jev_L3'),('intern_L1','qwen_L1'),('intern_L2','qwen_L2'),('intern_L3','qwen_L3'),('lora_L1','qwen_L1'),('jev_L1','deepseek_L1'),('jev_L3','deepseek_L3')]
P={}
random.seed(20261123)
B=2000
boots=[[u for f in random.choices(fl,k=len(fl)) for u in fams[f]] for _ in range(B)]
for a,b in pairs:
    for k in (a,b):
        if k not in P: P[k]=preds(k)
    pa,pb=P[a],P[b]
    d=macro(units,pa)-macro(units,pb)
    ds=sorted(macro(s,pa)-macro(s,pb) for s in boots)
    lo,hi=ds[int(.025*B)],ds[int(.975*B)]
    # mcnemar
    y=lambda u:1 if u.endswith('__bad') else 0
    n01=sum(1 for u in units if (pa.get(u)==y(u)) and (pb.get(u)!=y(u)))
    n10=sum(1 for u in units if (pa.get(u)!=y(u)) and (pb.get(u)==y(u)))
    n=n01+n10; k=min(n01,n10)
    p=min(1,2*sum(math.comb(n,i) for i in range(k+1))/2**n) if n else 1
    print(f"{a:10s} - {b:12s} Δ={d:+.4f} CI[{lo:+.4f},{hi:+.4f}]  a_only_right={n01:4d} b_only_right={n10:4d} p={p:.2g}")
