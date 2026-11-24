# Parent peek (2026-11-24, PRELIMINARY, diagnostic only): which L4-D fact type costs the most?
# For each layer, replace the model's answers of one qtype group by the gold answers, re-derive with the
# frozen rules (l4d/derive.py, same per-fold tau), and score pooled eval macro-F1. Nothing here is a reported
# method; it only says where the errors are.
import json, subprocess, os, sys
R = '/home/barton/Documents/projects/cs224/cs224proj/juliet_full/'
TAU = {0: 0.817574, 1: 0.5, 2: 0.5}
GROUPS = {'none': set(), 'exec_any+exec_all': {'exec_any', 'exec_all'}, 'exec_all': {'exec_all'},
          'exec_any': {'exec_any'}, 'rel': {'rel'}, 'heap': {'heap'}, 'realloc_safe': {'realloc_safe'},
          'all': {'heap', 'exec_any', 'exec_all', 'rel', 'realloc_safe'}}
lab = {}
for l in open(R + 'data/build/layer1.jsonl'):
    u = json.loads(l); lab[u['unit_id']] = (u['label'] == 'bad', u['fold'], u['set'])


def mf1(pr):
    tp = fp = tn = fn = 0
    for u, p in pr.items():
        y = lab[u][0]; p = p == 1
        tp += p and y; fp += p and not y; fn += (not p) and y; tn += (not p) and not y
    f = lambda a, b, c: 2 * a / (2 * a + b + c) if a else 0
    return (f(tp, fp, fn) + f(tn, fn, fp)) / 2, fp, fn


layers = sys.argv[1:] or ['layer1', 'layer3', 'placebo']
tmp = '/tmp/l4dpeek2/attr'; os.makedirs(tmp, exist_ok=True)
for lay in layers:
    gold = {}
    for l in open(R + f'l4d/build/questions_{lay}.jsonl'):
        q = json.loads(l); gold[q['qid']] = (q['qtype'], q['gold'])
    print(f'== {lay}')
    for gname, gs in GROUPS.items():
        pooled = {}
        for k in range(3):
            src = f'/tmp/l4dpeek2/{lay}_f{k}.jsonl'
            dst = f'{tmp}/{lay}_f{k}_{gname}.jsonl'
            with open(dst, 'w') as o:
                for l in open(src):
                    r = json.loads(l)
                    qt, g = gold[r['qid']]
                    if qt in gs:
                        r['p_yes'] = 1.0 if g == 1 or g is True else 0.0
                    o.write(json.dumps(r) + '\n')
            out = f'{tmp}/{lay}_f{k}_{gname}_units.jsonl'
            subprocess.run([R + 'l4d/.venv/bin/python', R + 'l4d/derive.py', '--questions',
                            R + f'l4d/build/questions_{lay}.jsonl', '--answers', dst, '--tau', str(TAU[k]),
                            '--out', out], check=True, capture_output=True)
            for l in open(out):
                r = json.loads(l)
                u = r['unit_id']
                if u in lab and lab[u][2] == 'eval' and lab[u][1] == k:
                    pooled[u] = r.get('pred')
        m, fp, fn = mf1(pooled)
        print(f'   gold {gname:18s} macro-F1 {m:.3f}  FP {fp:4d} FN {fn:4d}  (n={len(pooled)})')
