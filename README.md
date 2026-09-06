# payroll-sandbox v5 — CWE-862 + ambiguous-receiver sinks

A minimal Spring Boot app whose privileged payroll endpoints are reachable with
no authorization guard. Not a real product; source is parsed, never deployed.

v5 adds a second axis on top of v2's CWE-862 corpus: sinks whose receiver class
is ambiguous by simple name, so `sink_type_reasoning` cannot settle them from
the graph and must escalate to the LLM. See the second table below.

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

## Ambiguous-receiver sinks (`PayrollAuditService.java`)

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
