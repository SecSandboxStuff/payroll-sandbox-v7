# payroll-sandbox v7 — new sinks, no reuse (LLM path only)

A minimal Spring Boot app whose privileged payroll endpoints are reachable with
no authorization guard. Not a real product; source is parsed, never deployed.

v7 is the third leg of the v5/v6 pair. It keeps the same three ambiguous
receiver families, so every sink still escapes the graph confirm and reaches the
Phase 2 LLM — but nothing in it is content-identical to an earlier sandbox, so
the reasoning DB cannot answer and each site is asked fresh.

| Repo | Sinks reach LLM? | Verdicts from DB? | Expected |
|---|---|---|---|
| v5 | yes | no (first run) | `llm > 0` |
| v6 | n/a — reused | yes | `llm = 0` |
| v7 | yes | no (novel snippets) | `llm > 0` |

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

## Ambiguous-receiver sinks (`PayrollDisbursementService.java`)

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

## Why nothing here hits the reasoning DB

The cache key is `(sink_symbol, content-hash(snippet))`, the snippet being ±10
lines around the call, clamped to the enclosing function and normalized for
trailing whitespace only — **leading indentation is significant**. v6 exploited
that by holding the snippet fixed. v7 breaks it on every axis at once:

- different receivers (`audit` not `log`, `gatewayClient` not `httpClient`)
- different arguments, message strings and local variable names
- calls restructured into `try`/`catch`, `for` and `if` blocks, so the sinks sit
  at a different indentation depth
- different surrounding statements inside every ±10 window

Verified: all 6 snippet hashes are disjoint from v5's and v6's.

What is deliberately *unchanged* is what keeps the sites escalating in the first
place — the ambiguous simple class names (`Logger` → slf4j / log4j / j.u.l,
`EntityManager` → jakarta / javax, `HttpClient` → java.net.http / apache) and the
sink-relevant imports. Both `entityManager.find(...)` sites still match the
CWE-639 catalog `grep_pattern`.

## Sinks

| # | Method | Sink | CWE / type |
|---|--------|------|------------|
| 1 | `loadDisbursement` | `entityManager.find(Salary.class, batchRef)` | 639, IDOR_LOOKUP |
| 2 | `settleDisbursement` | `entityManager.find(Salary.class, batchRef)` | 639, IDOR_LOOKUP |
| 3 | `settleDisbursement` | `audit.info(...)` | 312, LOG_WRITE |
| 4 | `settleDisbursement` | `audit.error(...)` | 312/319, LOG_WRITE |
| 5 | `traceDisbursementRun` | `audit.warn(...)` | 312, LOG_WRITE |
| 6 | `transmitBatch` | `gatewayClient.send(...)` | 319, NETWORK_WRITE |

The four entry points reaching these are role-guarded on purpose, so they add no
CWE-862 findings and leave the ground truth above untouched.

## Expected result

`llm > 0` on every scan, cold or warm-from-DB, with no `[REASONING-DB PULL] hit`
lines for these six. A *second* scan of v7 will hit the local cache (and the DB)
— the no-reuse property holds for the first scan, which is the point.
