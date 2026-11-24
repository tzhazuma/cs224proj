"""Structure-only baseline for L4-D: answer every fact question "yes" (p_yes = 1.0),
derive with the frozen v1 rules (tau 0.5), and score on eval. This measures how much the
parser + rules alone contribute, without any model. Run from the repo root."""
import json, subprocess, os
R = 'juliet_full/'
OUT = R + 'analysis/l4d_const/'
for layer in ['layer1', 'layer3', 'placebo', 'original']:
    ans = f'/tmp/l4dconst_{layer}.jsonl'
    with open(ans, 'w') as w:
        for l in open(R + f'l4d/build/questions_{layer}.jsonl'):
            q = json.loads(l)
            if q['set'] == 'eval':
                w.write(json.dumps({'qid': q['qid'], 'unit_id': q['unit_id'], 'qtype': q['qtype'], 'p_yes': 1.0}) + '\n')
    units = OUT + f'allyes_{layer}_units.jsonl'
    subprocess.run(['python3', R + 'l4d/derive.py', '--questions', R + f'l4d/build/questions_{layer}.jsonl',
                    '--answers', ans, '--tau', '0.5', '--method', 'l4d_const_allyes', '--out', units], check=True)
    d = json.loads(subprocess.run(['python3', R + 'analysis/score.py', '--pred', units, '--set', 'eval', '--json'],
                                  capture_output=True, text=True, check=True).stdout)['end_to_end']
    print(f"{layer:9s} TP {d['tp']:4d} FP {d['fp']:4d} TN {d['tn']:4d} FN {d['fn']:4d} macro-F1 {d['macro_f1']:.3f}")
