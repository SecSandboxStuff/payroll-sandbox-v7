# payroll-sandbox v6 — same sinks, moved (reasoning-DB reuse)

A minimal Spring Boot app whose privileged payroll endpoints are reachable with
no authorization guard. Not a real product; source is parsed, never deployed.

v6 carries v5's ambiguous-receiver sinks unchanged **in content** while moving
them in the file and renaming everything around them. It is the negative twin
of v5: v5 proves the sites reach the LLM, v6 proves they are then reused from
the reasoning DB instead of being re-asked.

Every sink target is **app-selected** — no request parameter names the record —
so an unguarded handler here is CWE-862, not CWE-639.

## Ground truth

| # | Handler | Route | Sink | Guard | Expected |
|---|---------|-------|------|-------|----------|
| 1 | `listSalaries` | `GET /admin/salaries` | `findAll()` | none | **TP** (AUTHZ_READ) |
| 2 | `salaryReport` | `GET /admin/salaries/report` | `findAll()` | `@PreAuthorize("hasRole('ADMIN')")` | safe |
| 3 | `headcount` | `GET /admin/salaries/headcount` | `count()` | none | **TP** (AUTHZ_READ) |
| 4 | `recalculate` | `POST /admin/salaries/recalculate` | `findAll()` + `saveAll()` | none | **TP ×2** (READ + WRITE) |
| 5 | `publish` | `POST /admin/salaries/publish` | `saveAll()` | `@Secured("ROLE_PAYROLL_ADMIN")` | safe |

5 true positives across 4 unguarded sink call sites; 2 guarded twins that must
not fire. All CWE-862 sites are in `SalaryController.java`.

`count()` is the grep-gated symbol in the catalog (bare `.count(` collides with
`Stream#count`), so it is written as `salaryRepository.count()` to match on the
receiver.

## Ambiguous-receiver sinks (`PayrollLedgerService.java`)

A second axis, added to exercise **sink type reasoning's LLM path**. Each
receiver's simple class name maps to more than one qualified class in the
catalog, so `compute_ambiguous_simple_classes` marks it ambiguous and
`neo4j_type_confirm` refuses to attribute the call — the site falls through
Phase 0/1 to the Phase 2 LLM.

| # | Method | Sink | Simple class collides across | Expected |
|---|--------|------|------------------------------|----------|
| 6 | `lookupSalary` | `entityManager.find(Salary.class, id)` | `jakarta.` / `javax.persistence` | **TP** (CWE-639, IDOR_LOOKUP) |
| 7 | `lookupForAdjustment` | `entityManager.find(Salary.class, employeeId)` | same | **TP** (CWE-639) |
| 8 | `lookupForAdjustment` | `log.warn(...)` | slf4j / log4j / `java.util.logging` | **TP** (CWE-312) |
| 9 | `auditPayout` | `log.info(...)` | same | **TP** (CWE-312) |
| 10 | `auditFailure` | `log.error(...)` | same | **TP** (CWE-312/319) |
| 11 | `exportSalaries` | `httpClient.send(...)` | `java.net.http` / apache | **TP** (CWE-319, NETWORK_WRITE) |

The three entry points reaching these are role-guarded on purpose, so they add
no CWE-862 findings and leave the table above untouched.

## What v6 changes (and deliberately does not)

`sink_type_reasoning` keys its cache on `(sink_symbol, content-hash(snippet))`,
where the snippet is ±10 lines around the call, clamped to the enclosing
function and normalized for trailing whitespace only. Identity is the code
content, never `(file, row)`.

So v6 changes everything *outside* those windows and nothing inside them:

| Changed | Unchanged (inside every snippet window) |
|---|---|
| Class renamed `PayrollAuditService` → `PayrollLedgerService` | the six sink call lines, byte for byte |
| File renamed to match | the ±10 lines of context around each |
| 30-line header added, shifting all six sinks down 3 lines | the sink-relevant imports, so `needs_llm[0]` resolves the same |
| Controller field, ctor, method names and all three routes renamed | leading indentation everywhere in range |

Sink line numbers move `38→41, 43→46, 44→47, 50→53, 55→58, 64→67`; all six
snippet hashes are identical.

## Expected result

A **cold** scan (empty `inc_dir`, repo never scanned) should report
`llm=0` for all six, sourced from the org-level DB rather than the local cache:

```
[REASONING-DB PULL] hit ns=sink_type_reasoning key=h2:… (reused cached verdict — no LLM)
[sink_type_reasoning] Phase 0+1 (neo4j+cache+filter): N confirmed, 0 need LLM
```

Two preconditions, or this falls back to the LLM and proves nothing:
1. **v5 must have been scanned first** — it is what commits the verdicts.
2. **The reasoning-DB client must be configured.** `get_reasoning_cache_client()`
   returning `None` degrades silently to the LLM path; the local per-project
   cache cannot help, since a fresh repo starts cold.

`IDOR_LOOKUP` opts out of receiver grouping, so #6 and #7 cost one LLM call
each; the `log.*` sites group by `(symbol, receiver)`, so `info`/`warn`/`error`
are three groups on one receiver, not one.

## Layout

```
pom.xml
src/main/java/com/secsandbox/payroll/
    PayrollApplication.java   @EnableMethodSecurity(securedEnabled = true)
    SalaryController.java     all sinks live here
    Salary.java               @Entity
    SalaryRepository.java     extends JpaRepository -> inherits the sinks
src/main/resources/application.properties
```
