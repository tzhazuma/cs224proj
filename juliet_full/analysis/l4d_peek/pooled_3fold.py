# Parent peek (2026-11-24 06:15 PST, PRELIMINARY): LoRA L4-D pooled over the 3 held-out folds on
# layer1 / layer3 / placebo (original folds 1-2 still running). Inputs: answers copied from 184-toast
# to /tmp/l4dpeek2/<layer>_f<k>.jsonl, derived with l4d/derive.py (tau fold0 0.817574, folds 1-2 0.5)
# into /tmp/l4dpeek2/<layer>_f<k>_units.jsonl. Pruned (opt.) inference gives identical verdicts.
import json, random, glob
R = '/home/barton/Documents/projects/cs224/cs224proj/juliet_full/'
lab = {}
for l in open(R + 'data/build/layer1.jsonl'):
    u = json.loads(l)
    lab[u['unit_id']] = dict(y=u['label'] == 'bad', fold=u['fold'], set=u['set'], fam=u['family'],
                             grp=u['group_id'], flow=u['flow_category'], gk=u.get('good_kind'))
subs = json.load(open(R + 'data/build/subsets.json'))
n25, api = set(subs['nested25']), set(subs['api_subset'])


def load(p):
    d = {}
    for l in open(p):
        r = json.loads(l)
        d[r['unit_id']] = r.get('pred')
    return d


def loads(*ps):
    d = {}
    for p in ps:
        d.update(load(p))
    return d


def mf1(ids, pr):
    tp = fp = tn = fn = 0
    for u in ids:
        y = lab[u]['y']; p = pr.get(u) == 1
        tp += p and y; fp += p and not y; fn += (not p) and y; tn += (not p) and not y
    f = lambda a, b, c: 2 * a / (2 * a + b + c) if a else 0
    return (f(tp, fp, fn) + f(tn, fn, fp)) / 2, fp, fn


def boot(ids, a, b, B=2000, seed=20261123):
    fam = {}
    for u in ids:
        fam.setdefault(lab[u]['fam'], []).append(u)
    ks = list(fam); rng = random.Random(seed); ds = []
    for _ in range(B):
        s = [u for k in (rng.choice(ks) for _ in ks) for u in fam[k]]
        ds.append(mf1(s, a)[0] - mf1(s, b)[0])
    ds.sort(); return ds[int(.025 * B)], ds[int(.975 * B)]


L = {}
for lay in ['layer1', 'layer3', 'placebo', 'original']:
    d = {}
    for k in range(3):
        for u, p in load(f'/tmp/l4dpeek2/{lay}_f{k}_units.jsonl').items():
            if u in lab and lab[u]['set'] == 'eval' and lab[u]['fold'] == k:
                d[u] = p
    L[lay] = d

D = R + 'llm/results/deepseek_flash/'
J = R + 'llm/results/jev/'
refs = {
    'layer1': [('DeepSeek L1', load(D + 'layer1/eval_L1_r1.jsonl'), 'all'),
               ('DeepSeek L2', load(D + 'layer1/eval_L2_r1.jsonl'), 'all'),
               ('Jev L3', load(J + 'layer1/eval_L3_r1.jsonl') if glob.glob(J + 'layer1/eval_L3_r1.jsonl') else None, 'all')],
    'layer3': [('DeepSeek L1', load(D + 'layer3/l3_n25_L1_r1.jsonl'), 'n25'),
               ('DeepSeek L4', load(D + 'layer3/l3_n25_L4_r1.jsonl'), 'n25'),
               ('DeepSeek L1', loads(D + 'layer3/l3_n25_L1_r1.jsonl', D + 'layer3/l3_apirest_L1_r1.jsonl'), 'api'),
               ('DeepSeek L3', loads(D + 'layer3/l3_n25_L3_r1.jsonl', D + 'layer3/l3_apirest_L3_r1.jsonl'), 'api'),
               ('DeepSeek L1', load(D + 'layer3/l3_eval_L1_r1.jsonl'), 'all'),
               ('DeepSeek L4', load(D + 'layer3/l3_eval_L4_r1.jsonl'), 'all'),
               ('Jev L3', load(J + 'layer3/l3_eval_L3_r1.jsonl'), 'all')],
    'placebo': [('DeepSeek L1', load(D + 'placebo/pl_n25_L1_r1.jsonl'), 'n25'),
                ('DeepSeek L3', load(D + 'placebo/pl_n25_L3_r1.jsonl'), 'n25'),
                ('Jev L3', load(J + 'placebo/pl_eval_L3_r1.jsonl'), 'all')],
    'original': [('DeepSeek L1', load(D + 'original/orig_n25_L1_r1.jsonl'), 'n25'),
                 ('Jev L1', load(J + 'original/orig_eval_L1_r1.jsonl'), 'all')],
}
for lay, d in L.items():
    ids_all = sorted(d)
    m, fp, fn = mf1(ids_all, d)
    inv = sum(1 for u in ids_all if d[u] is None)
    perfold = [round(mf1([u for u in ids_all if lab[u]['fold'] == k], d)[0], 3) for k in range(3)]
    print(f'== {lay}: L4-D pooled n={len(ids_all)} macro-F1 {m:.3f} FP {fp} FN {fn} invalid {inv} per-fold {perfold}')
    for nm, pr, scope in refs[lay]:
        if pr is None:
            continue
        ids = [u for u in ids_all if scope == 'all' or (scope == 'n25' and lab[u]['grp'] in n25) or (scope == 'api' and lab[u]['grp'] in api)]
        ma = mf1(ids, d)[0]; mb = mf1(ids, pr)[0]; lo, hi = boot(ids, d, pr)
        near = 'near' if ma >= mb - 0.02 else 'NOT near'
        eq = 'equiv' if lo >= -0.02 else 'not equiv'
        print(f'   vs {nm:12s} [{scope}, n={len(ids)}]: L4-D {ma:.3f} vs {mb:.3f}  Δ {ma-mb:+.3f} [{lo:+.3f},{hi:+.3f}]  {near}, {eq}')
    # error breakdown
    bad_fn = {}
    good_fp = {}
    for u in ids_all:
        if lab[u]['y'] and d[u] != 1:
            bad_fn[lab[u]['flow']] = bad_fn.get(lab[u]['flow'], 0) + 1
        if not lab[u]['y'] and d[u] == 1:
            good_fp[lab[u]['gk']] = good_fp.get(lab[u]['gk'], 0) + 1
    print('   FN by flow', dict(sorted(bad_fn.items())), ' FP by good_kind', good_fp)
