import json, subprocess, sys
TAU=0.817574
def needed(q):
    t,k=q['qtype'],q['site_kinds']
    if t=='heap': return k[0]=='alloc'
    if t=='exec_any': return k[0] in ('alloc','realloc')
    if t=='exec_all': return k[0] in ('release','realloc')
    return t in ('rel','realloc_safe')
for lay,af in [('layer1','l1_f0'),('layer3','l3_f0'),('placebo','placebo_f0'),('original','original_f0')]:
    full=[json.loads(l) for l in open(f'build/questions_{lay}.jsonl')]
    full=[q for q in full if q['set']=='eval' and q['fold']==0]
    with open(f'/tmp/l4dpeek/q_full_{lay}.jsonl','w') as f:
        for q in full: f.write(json.dumps(q)+'\n')
    with open(f'/tmp/l4dpeek/q_need_{lay}.jsonl','w') as f:
        n=0
        for q in full:
            if needed(q): f.write(json.dumps(q)+'\n'); n+=1
    out={}
    for tag in ('full','need'):
        o=f'/tmp/l4dpeek/u_{tag}_{lay}.jsonl'
        r=subprocess.run([sys.executable,'derive.py','--questions',f'/tmp/l4dpeek/q_{tag}_{lay}.jsonl','--answers',f'/tmp/l4dpeek/{af}.jsonl','--tau',str(TAU),'--out',o,'--souffle'],capture_output=True,text=True)
        assert r.returncode==0, r.stderr
        out[tag]={json.loads(l)['unit_id']:json.loads(l) for l in open(o)}
    a,b=out['full'],out['need']
    zero=[u for u in a if u not in b]
    for u in zero: b[u]={'pred':0,'score':0.0,'status':'ok','extra':{'leaks':[]}}
    zp=sum(a[u]['pred'] for u in zero)
    dp=sum(a[u]['pred']!=b[u]['pred'] for u in a); ds=max(abs(a[u]['score']-b[u]['score']) for u in a)
    dl=sum(a[u]['extra']['leaks']!=b[u]['extra']['leaks'] for u in a)
    print(f'{lay:9s} units {len(a)} questions {len(full)} -> {n} ({n/len(full):.0%}) | pred diffs {dp} | leak-list diffs {dl} | max score diff {ds:.2e} | invalid {sum(b[u]["status"]!="ok" for u in b)} | units needing 0 questions {len(zero)} (full-run pred=1 among them: {zp})')
