# Juliet CWE-401 source cleaning audit

Generated at 2026-11-11T19:19:46+00:00 UTC.

- Input: `juliet/subset_units.jsonl` (frozen, read-only)
- Units: 200 ({'dev': 60, 'test': 140})
- Labels: {'bad': 100, 'good': 100}
- Languages: {'cpp': 112, 'c': 88}
- Prompt version: `juliet-llm-binary-2026-11-12.1`
- Prompt construction code: `juliet_llm/cleaning.py`, `juliet_llm/prompting.py`

## Pipeline

1. Strip `//` and `/* */` comments with a string-literal-aware scanner.
2. Resolve `#ifdef`/`#ifndef`/`#endif` with the unit's compile defines, keeping
   only the branch that the frozen build compiles.
3. Inline unit-local headers referenced by quoted `#include` directives; drop
   the support header.
4. Rename every identifier containing `bad`, `good`, `cwe`, or `memory_leak`
   to a unit-local `sym_N` name; scrub string literals with the same token set.
5. Audit the result; the build fails if any forbidden token survives.

## Forbidden-token counts

Counts are token occurrences over the concatenated raw sources and over the
final cleaned source views. `source_path` covers `raw/testcases`, `/mnt/`, and
`juliet/`.

| Pattern | Raw sources | Cleaned views |
| --- | ---: | ---: |
| `label_bad` | 3324 | 0 |
| `label_good` | 5110 | 0 |
| `cwe` | 2054 | 0 |
| `memory_leak` | 2042 | 0 |
| `omit_macro` | 1908 | 0 |
| `flaw_marker` | 736 | 0 |
| `support_header` | 290 | 0 |
| `source_path` | 0 | 0 |

The cleaned counts are all zero; every cleaned unit passed the audit.

## Per-unit checks

| Check | Passed |
| --- | ---: |
| `braces_balanced` | 200/200 |
| `forbidden_tokens_absent` | 200/200 |
| `group_id_absent` | 200/200 |
| `no_comment_residue` | 200/200 |
| `no_conditional_directives` | 200/200 |
| `no_empty_parts` | 200/200 |
| `nonempty` | 200/200 |
| `unit_id_absent` | 200/200 |

## Examples

### CWE401_Memory_Leak__char_calloc_33__bad

Original (label-bearing) excerpt:

```c
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__char_calloc_33.cpp
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-33.tmpl.cpp
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 33 Data flow: use of a C++ reference to data within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__char_calloc_33
{

#ifndef OMITBAD

void bad()
{
```

Cleaned excerpt:

```c
// ---- part 1 ----
#include <wchar.h>

namespace sym_0
{

void sym_1()
{
    char * data;
    char * &dataRef = data;
    data = NULL;

    data = (char *)calloc(100, sizeof(char));
    if (data == NULL) {exit(-1);}

    strcpy(data, "A String");
    printLine(data);
    {
        char * data = dataRef;

        ;
    }
}

}

using namespace sym_0;

```

### CWE401_Memory_Leak__char_calloc_01__good

Original (label-bearing) excerpt:

```c
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE401_Memory_Leak__char_calloc_01.c
Label Definition File: CWE401_Memory_Leak.c.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 401 Memory Leak
 * BadSource: calloc Allocate data using calloc()
 * GoodSource: Allocate data on the stack
 * Sinks:
 *    GoodSink: call free() on data
 *    BadSink : no deallocation of data
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE401_Memory_Leak__char_calloc_01_bad()
{
    char * data;
    data = NULL;
    /* POTENTIAL FLAW: Allocate memory on the heap */
```

Cleaned excerpt:

```c
// ---- part 1 ----
#include <wchar.h>

static void sym_0()
{
    char * data;
    data = NULL;

    data = (char *)ALLOCA(100*sizeof(char));

    strcpy(data, "A String");
    printLine(data);

    ;
}

static void sym_1()
{
    char * data;
    data = NULL;

    data = (char *)calloc(100, sizeof(char));
    if (data == NULL) {exit(-1);}

    strcpy(data, "A String");
    printLine(data);

    free(data);
```

