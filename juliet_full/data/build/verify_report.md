# Label verification (verify_labels.py)

gcc/g++ 13 `-fsanitize=address -g -O0`, run with `ASAN_OPTIONS=detect_leaks=1` and `LSAN_OPTIONS=use_stacks=0` (primary), stdin closed, 10 s timeout; clang/clang++ 23 compile+link check; valgrind 3.28 `--leak-check=full` (definite/indirect) on a stratified sample. Labels are never changed; mismatches are recorded in `verify.note`.

## Compile rates

| layer | units | gcc ok | clang ok |
|---|---|---|---|
| layer1 | 3316 | 3316 | 3316 |
| original | 3316 | 3316 | 3316 |

## LSan agreement with the Juliet label by mechanism (layer1; original good in last column)

| mechanism | bad: leak reported | good (layer1): no leak | good (orig): no leak |
|---|---|---|---|
| c_alloc | 914/960 | 960/960 | 960/960 |
| cpp_new | 558/588 | 588/588 | 588/588 |
| destructor | 2/2 | 2/2 | 2/2 |
| realloc_fail | 0/108 | 108/108 | 108/108 |

## LSan agreement with the Juliet label by flow_category (layer1; original good in last column)

| flow_category | bad: leak reported | good (layer1): no leak | good (orig): no leak |
|---|---|---|---|
| 01 | 36/42 | 42/42 | 42/42 |
| 02-22 | 638/748 | 748/748 | 748/748 |
| 31-45 | 244/278 | 278/278 | 278/278 |
| 51-68 | 346/380 | 380/380 | 380/380 |
| 71-84 | 210/210 | 210/210 | 210/210 |

## Mismatch reasons (layer1)

| label | reason | units |
|---|---|---|
| bad | memory still reachable from a global at exit | 68 |
| bad | realloc_fail (leak needs realloc failure) | 108 |
| bad | variant 12 random branch | 8 |

- layer1 units where default LSan options (stacks as roots) disagree with the primary run: {'bad': 175} (stale -O0 stack slots in the exited frames hide the leak)
- other ASan errors (layer1): {'attempting free on address which was not malloc': 16}

## Valgrind sample (layer1)

| label | units | valgrind agrees with label | valgrind agrees with LSan |
|---|---|---|---|
| bad | 100 | 87 | 99 |
| good | 100 | 100 | 100 |
