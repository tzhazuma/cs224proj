# L4 fact schema v3 (LLM fact extraction → grounding check → Souffle)

Pipeline per unit: `prompts/l4_system.txt` + `prompts/l4_user.txt` (code shown with `<n>| ` line numbers,
`llmlane/prompts.py:number_lines`) → DeepSeek lists facts → `llmlane/l4.py:parse_facts(text, model_text)` →
`l4/leak.dl` (Souffle 2.5) → pred = 1 iff `leak/2` is non-empty. JSON mode is off for L4.

| fact | meaning | grounding check (cited line must contain) |
|---|---|---|
| `alloc(Obj, Var, Func, Line)` | `Var = malloc/calloc/strdup/wcsdup/new/new[]` in Func; Obj fresh id | `malloc\|calloc\|strdup\|wcsdup\|new` and Var |
| `realloc(Obj, Dst, Src, Func, Line)` | `Dst = realloc(Src, …)`; Obj = block realloc returns | `realloc` and Dst or Src |
| `free(Var, Func, Line)` | `free(Var)`, `delete Var`, `delete[] Var` | `free\|delete` and Var |
| `assign(Dst, Src, Func, Line)` | pointer copy | Dst or Src |
| `pass(Callee, Param, Arg, Func, Line)` | Arg (or &Arg, or a reference) bound to Param of Callee | Callee or Arg |
| `retval(Dst, Callee, Func, Line)` | Dst = Callee(...) | Dst or Callee |
| `ret(Func, Var, Line)` | `return Var` | `return` and Var |
| `call(Caller, Callee, Line)` | call edge (destructor of local/deleted object = `Class::~Class`) | line exists |
| `global(Var)` | global or file-level static | – |
| `dead(Line)` | statement on Line is in a never-executing branch | line exists |

Names: `Var.field`, `Var[]` (array or container element), `Class::member` (one global scope), `*p` → `p`,
`->` → `.`. "Has a name on the line" = an identifier of the fact argument occurs as a word on that line.
Facts failing the check are dropped (`extra.ungrounded`), not counted as parse errors. Fact name alias:
`delete(Var, Func, Line)` is read as `free` (`llmlane/l4.py:FACT_ALIASES`).

Rules (`l4/leak.dl`): reachability from `main` over non-dead `call`/`pass`/`retval`; flow-insensitive
inclusion points-to over (function, variable) nodes (globals and `Class::member` share scope `@global`;
parameters alias arguments both ways); facts on dead lines are ignored.
- `freed(o)`: a reachable non-dead `free(v)` with `o ∈ pts(v)`; or a `realloc(n, _, src)` with `o ∈ pts(src)`, `o ≠ n`
  (realloc releases the old block on success).
- `leak(o, never_freed)`: an allocated object (alloc or realloc result) that is never freed.
- `leak(o, realloc_fail)`: `realloc(n, v, v, …)` (result stored back into the pointer it reallocates) and
  `o ∈ pts(v)`, `o ≠ n`: on failure NULL overwrites the only pointer to the old block.

Metrics (dev only): parse rate = share of answers whose every non-empty line is a well-formed fact (or `none`);
grounded share = kept facts / (kept + ungrounded); agreement = pred == truth (invalid counted wrong).

History: v1 (scratch/l4_system_v1.txt) and v2 (scratch/l4_system_v2.txt, scratch/leak_v2.dl): facts without
lines, `realloc_fail(Obj, Func)` judged by the model and `dead(Func, Var, Kind)`; v2 failures were identical
facts for leaking/fixed realloc versions and one hallucinated free.
