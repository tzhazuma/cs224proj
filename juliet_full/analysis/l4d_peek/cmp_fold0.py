import json, random, glob
R='/home/barton/Documents/projects/cs224/cs224proj/juliet_full/'
lab={}
for l in open(R+'data/build/layer1.jsonl'):
    u=json.loads(l); lab[u['unit_id']]=(u['label']=='bad',u['fold'],u['set'],u['family'] if 'family' in u else u['group_id'])
sub=json.load(open(R+'data/build/subsets.json'))['nested25']
n25=set(sub if isinstance(sub,list) else sub.get('groups',sub))
def load(p):
    d={}
    for l in open(p):
        r=json.loads(l); d[r['unit_id']]=r.get('pred')
    return d
def mf1(ids,pr):
    tp=fp=tn=fn=0
    for u in ids:
        y=lab[u][0]; p=pr.get(u)==1
        tp+=p and y; fp+=p and not y; fn+=(not p) and y; tn+=(not p) and not y
    f=lambda a,b,c:2*a/(2*a+b+c) if a else 0
    return (f(tp,fp,fn)+f(tn,fn,fp))/2
def boot(ids,a,b,B=2000,seed=20261123):
    fam={}
    for u in ids: fam.setdefault(lab[u][3],[]).append(u)
    ks=list(fam); rng=random.Random(seed); ds=[]
    for _ in range(B):
        s=[u for k in (rng.choice(ks) for _ in ks) for u in fam[k]]
        ds.append(mf1(s,a)-mf1(s,b))
    ds.sort(); return ds[int(.025*B)],ds[int(.975*B)]
F=R
lays={'layer1':('l1_units.jsonl','layer1',''),'layer3':('l3_units.jsonl','layer3','l3_'),'placebo':('placebo_units.jsonl','placebo','pl_'),'original':('original_units.jsonl','original','orig_')}
for lay,(uf,d,pre) in lays.items():
    l4=load('/tmp/l4dpeek/'+uf)
    ids=[u for u in l4 if u in lab and lab[u][2]=='eval' and lab[u][1]==0]
    rows=[('LoRA L4-D (fold0)',l4)]
    for s in ['L1','L3']:
        p=F+f'decision_ft/results/decision_ft/{d}/{s}_cv_v1.jsonl'
        if glob.glob(p): rows.append((f'old LoRA {s}',load(p)))
    qn={'layer1':'eval_','layer3':'l3_eval_','placebo':'pl_eval_','original':'orig_eval_'}[lay]
    for s in ['L1','L2','L3','L4']:
        p=F+f'llm/results/qwen3_5_4b/{d}/{qn}{s}_r1.jsonl'
        if glob.glob(p): rows.append((f'Qwen gen {s}',load(p)))
    for s in ['L1','L2','L3']:
        p=F+f'gpu/results/intern_decision/{d}/{qn}{s}_r1.jsonl'
        if glob.glob(p): rows.append((f'Intern {s}',load(p)))
    print(f'== {lay} fold0 eval n={len(ids)}')
    for nm,pr in rows:
        cov=sum(u in pr for u in ids)
        extra=''
        if nm.startswith('old LoRA'):
            lo,hi=boot(ids,l4,pr); extra=f'  ΔL4D-this {mf1(ids,l4)-mf1(ids,pr):+.3f} [{lo:+.3f},{hi:+.3f}]'
        print(f'  {nm:20s} {mf1(ids,pr):.3f} (cov {cov}){extra}')
    # DeepSeek
    if lay=='layer1':
        ds=load(F+'llm/results/deepseek_flash/layer1/eval_L1_r1.jsonl'); sid=ids
    else:
        nm={'layer3':'l3_n25_L1_r1','placebo':'pl_n25_L1_r1','original':'orig_n25_L1_r1'}[lay]
        ds=load(F+f'llm/results/deepseek_flash/{d}/{nm}.jsonl'); sid=[u for u in ids if u.rsplit('__',1)[0] in n25]
    print(f'  DeepSeek L1 on n={len(sid)}: {mf1(sid,ds):.3f}  vs L4-D same units {mf1(sid,l4):.3f}')
