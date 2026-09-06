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
    private final PayrollDisbursementService disbursementService;

    public SalaryController(SalaryRepository salaryRepository, PayrollDisbursementService disbursementService) {
        this.salaryRepository = salaryRepository;
        this.disbursementService = disbursementService;
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

    // Role-guarded (so not CWE-862), but the caller still names the batch:
    // CWE-639 on the lookup.
    @PreAuthorize("hasRole('EMPLOYEE')")
    @GetMapping("/disbursements/{batchRef}")
    public Salary viewDisbursement(@PathVariable Long batchRef) {
        return disbursementService.loadDisbursement(batchRef);
    }

    // Role-guarded; CWE-639 on the lookup, CWE-312 on the settle/abort logs.
    @PreAuthorize("hasRole('PAYROLL_CLERK')")
    @PostMapping("/disbursements/{batchRef}/settle")
    public Salary settleDisbursement(@PathVariable Long batchRef, @RequestBody String approver) {
        return disbursementService.settleDisbursement(batchRef, approver);
    }

    // Role-guarded; CWE-312 — per-row payout detail hits the log.
    @Secured("ROLE_PAYROLL_ADMIN")
    @PostMapping("/admin/disbursements/trace")
    public void traceDisbursementRun(@RequestBody String runId) {
        disbursementService.traceDisbursementRun(salaryRepository.findAll(), runId);
    }

    // Role-guarded; CWE-319 — the batch leaves over plaintext http.
    @Secured("ROLE_PAYROLL_ADMIN")
    @PostMapping("/admin/disbursements/transmit")
    public int transmitBatch(@RequestBody String batchDocument) throws Exception {
        return disbursementService.transmitBatch(batchDocument, "run-" + System.nanoTime());
    }
}
