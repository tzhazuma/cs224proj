import json, collections, statistics as st, bisect
def needed(q):
    t,k=q['qtype'],q['site_kinds']
    if t=='heap': return k[0]=='alloc'
    if t=='exec_any': return k[0] in ('alloc','realloc')
    if t=='exec_all': return k[0] in ('release','realloc')
    return t in ('rel','realloc_safe')
P=lambda v,x: sorted(v)[int(x*(len(v)-1))]
ref={'DeepSeek L1':0.715,'Jev L1':0.907,'old LoRA L1':0.105}
for lay,af in [('layer1','l1_f0'),('layer3','l3_f0'),('placebo','placebo_f0'),('original','original_f0')]:
    nq=collections.Counter(); nn=collections.Counter()
    for l in open(f'q_full_{lay}.jsonl'):
        q=json.loads(l); nq[q['unit_id']]+=1; nn[q['unit_id']]+=needed(q)
    t={}
    for l in open(f'{af}.jsonl'):
        r=json.loads(l); t.setdefault(r['unit_id'],r['unit_forward_s'])
    byn=collections.defaultdict(list)
    for u,n in nq.items(): byn[n].append(t[u])
    ks=sorted(byn); med={k:st.median(byn[k]) for k in ks}
    def est(m):
        if m==0: return 0.0
        if m<=ks[0]: return med[ks[0]]*m/ks[0]
        if m>=ks[-1]: return med[ks[-1]]*m/ks[-1]
        i=bisect.bisect_left(ks,m)
        if ks[i]==m: return med[m]
        a,b=ks[i-1],ks[i]; return med[a]+(med[b]-med[a])*(m-a)/(b-a)
    now=[t[u] for u in nq]; new=[est(nn[u]) for u in nq]
    print(f'{lay:9s} now med {st.median(now):.2f}s p90 {P(now,.9):.2f}s total {sum(now)/60:.1f}min | pruned est med {st.median(new):.2f}s p90 {P(new,.9):.2f}s total {sum(new)/60:.1f}min | speedup med {st.median(now)/st.median(new):.1f}x total {sum(now)/sum(new):.1f}x | zero-q units {sum(1 for u in nq if nn[u]==0)}')
