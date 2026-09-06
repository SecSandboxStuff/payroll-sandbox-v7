package com.secsandbox.payroll;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Privileged payroll endpoints. Every target is app-selected — no request
 * parameter names the record — so an unguarded handler is CWE-862, not CWE-639.
 */
@RestController
public class SalaryController {

    private static final BigDecimal RAISE = new BigDecimal("1.03");

    private final SalaryRepository salaryRepository;
    private final PayrollLedgerService ledgerService;

    public SalaryController(SalaryRepository salaryRepository, PayrollLedgerService ledgerService) {
        this.salaryRepository = salaryRepository;
        this.ledgerService = ledgerService;
    }

    // VULNERABLE: dumps every salary row, no authz guard.
    @GetMapping("/admin/salaries")
    public List<Salary> listSalaries() {
        return salaryRepository.findAll();
    }

    // SAFE: same read, guarded by a role check.
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/salaries/report")
    public List<Salary> salaryReport() {
        return salaryRepository.findAll();
    }

    // VULNERABLE: discloses headcount, no authz guard.
    @GetMapping("/admin/salaries/headcount")
    public long headcount() {
        return salaryRepository.count();
    }

    // VULNERABLE: bulk raise applied to the whole table, no authz guard.
    @PostMapping("/admin/salaries/recalculate")
    public List<Salary> recalculate() {
        List<Salary> all = salaryRepository.findAll();
        all.forEach(s -> s.setAmount(s.getAmount().multiply(RAISE)));
        return salaryRepository.saveAll(all);
    }

    // SAFE: same bulk write, guarded by a role check.
    @Secured("ROLE_PAYROLL_ADMIN")
    @PostMapping("/admin/salaries/publish")
    public List<Salary> publish(@RequestBody List<Salary> revised) {
        return salaryRepository.saveAll(revised);
    }

    // Role-guarded (so not CWE-862), but the caller still names the record:
    // CWE-639 on the lookup, CWE-312 on the audit log.
    @PreAuthorize("hasRole('EMPLOYEE')")
    @GetMapping("/ledger/salaries/{id}")
    public Salary readLedgerEntry(@PathVariable Long id) {
        Salary salary = ledgerService.lookupSalary(id);
        ledgerService.auditPayout(salary);
        return salary;
    }

    // Role-guarded; CWE-639 on the second lookup site.
    @PreAuthorize("hasRole('PAYROLL_CLERK')")
    @PostMapping("/ledger/salaries/{id}/adjust")
    public Salary reviseLedgerEntry(@PathVariable Long id) {
        return ledgerService.lookupForAdjustment(id);
    }

    // Role-guarded; CWE-319 — the export leaves over plaintext http.
    @Secured("ROLE_PAYROLL_ADMIN")
    @PostMapping("/admin/ledger/export")
    public int archiveLedger(@RequestBody String payload) throws Exception {
        return ledgerService.exportSalaries(payload);
    }
}
