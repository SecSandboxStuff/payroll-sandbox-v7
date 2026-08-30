# payroll-sandbox — CWE-862 (Missing Authorization)

A minimal Spring Boot app whose privileged payroll endpoints are reachable with
no authorization guard. Not a real product; source is parsed, never deployed.

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
not fire. All sites are in `SalaryController.java`.

`count()` is the grep-gated symbol in the catalog (bare `.count(` collides with
`Stream#count`), so it is written as `salaryRepository.count()` to match on the
receiver.

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
