import json, collections, statistics as st
R='/home/barton/Documents/projects/cs224/cs224proj/juliet_full/'
TAU=0.817574
def run(layer, ansf):
    Q=collections.defaultdict(list)
    for l in open(R+f'l4d/build/questions_{layer}.jsonl'):
        q=json.loads(l)
        if q['set']=='eval' and q['fold']==0: Q[q['unit_id']].append(q)
    A={}; fw={}
    for l in open(ansf):
        r=json.loads(l); A[r['qid']]=r['p_yes']>=TAU; fw[r['unit_id']]=(r['unit_forward_s'],r['unit_n_questions'])
    # latency model: forward ~ a + b*n
    xs=[v[1] for v in fw.values()]; ys=[v[0] for v in fw.values()]
    mx,my=st.mean(xs),st.mean(ys); b=sum((x-mx)*(y-my) for x,y in zip(xs,ys))/sum((x-mx)**2 for x in xs); a=my-b*mx
    tot=[];need=[];lazy=[];rounds=[];same=0
    for u,qs in Q.items():
        kinds={}
        for q in qs:
            for s,k in zip(q['site_ids'],q['site_kinds']): kinds[s]=k
        allocs=[s for s,k in kinds.items() if k in('alloc','realloc')]
        rels=[s for s,k in kinds.items() if k in('release','realloc')]
        def qid(t,ss): return f"{layer}/{u}/{t}/{'+'.join(ss)}"
        nd=set()
        for a_ in allocs:
            if kinds[a_]=='alloc': nd.add(qid('heap',[a_]))
            nd.add(qid('exec_any',[a_]))
            if kinds[a_]=='realloc': nd.add(qid('realloc_safe',[a_]))
            for f in rels:
                if f!=a_: nd.add(qid('rel',[f,a_]))
        for f in rels: nd.add(qid('exec_all',[f]))
        have={q['qid'] for q in qs}; nd&=have
        tot.append(len(qs)); need.append(len(nd))
        # full derive with needed answers
        ans=lambda k: A.get(k,False)
        def leak_full():
            for a_ in allocs:
                hb = True if kinds[a_]=='realloc' else ans(qid('heap',[a_]))
                if not (hb and ans(qid('exec_any',[a_]))): continue
                freed=any(ans(qid('rel',[f,a_])) and ans(qid('exec_all',[f])) for f in rels if f!=a_)
                if kinds[a_]=='alloc' and not freed: return True
                if kinds[a_]=='realloc' and (not freed or not ans(qid('realloc_safe',[a_]))): return True
            return False
        # lazy in rounds: R1 heap(alloc)+exec_any(all allocs)+realloc_safe; R2 rel for live allocs; R3 exec_all for rel-yes frees
        asked=set(); r=0
        R1={qid('heap',[a_]) for a_ in allocs if kinds[a_]=='alloc'}|{qid('exec_any',[a_]) for a_ in allocs}|{qid('realloc_safe',[a_]) for a_ in allocs if kinds[a_]=='realloc'}
        R1&=have; asked|=R1; r+=1 if R1 else 0
        live=[a_ for a_ in allocs if (kinds[a_]=='realloc' or ans(qid('heap',[a_]))) and ans(qid('exec_any',[a_]))]
        R2={qid('rel',[f,a_]) for a_ in live for f in rels if f!=a_}&have; asked|=R2; r+=1 if R2 else 0
        cand={f for a_ in live for f in rels if f!=a_ and ans(qid('rel',[f,a_]))}
        R3={qid('exec_all',[f]) for f in cand}&have; asked|=R3; r+=1 if R3 else 0
        lazy.append(len(asked)); rounds.append(r)
    p=lambda v,x: sorted(v)[int(x*(len(v)-1))]
    print(f'{layer:9s} units {len(tot)} | questions/unit now median {st.median(tot)} p90 {p(tot,.9)} | rules-needed median {st.median(need)} p90 {p(need,.9)} ({sum(need)/sum(tot):.0%} of all) | lazy median {st.median(lazy)} p90 {p(lazy,.9)} ({sum(lazy)/sum(tot):.0%}), rounds median {st.median(rounds)} | fwd model {a:.3f}+{b:.3f}*n')
    est=lambda n: a+b*n
    print(f'{"":9s} est forward median: now {st.median([est(n) for n in tot]):.2f}s | pruned {st.median([est(n) for n in need]):.2f}s | lazy (1 fwd/round) {st.median([sum([0]) + est(n) + a*(rr-1) for n,rr in zip(lazy,rounds)]):.2f}s')
for lay,f in [('layer1','l1_f0.jsonl'),('layer3','l3_f0.jsonl'),('placebo','placebo_f0.jsonl'),('original','original_f0.jsonl')]:
    run(lay,f)
