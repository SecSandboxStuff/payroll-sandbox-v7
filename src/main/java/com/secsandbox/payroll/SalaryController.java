package com.secsandbox.payroll;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
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

    public SalaryController(SalaryRepository salaryRepository) {
        this.salaryRepository = salaryRepository;
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
}
