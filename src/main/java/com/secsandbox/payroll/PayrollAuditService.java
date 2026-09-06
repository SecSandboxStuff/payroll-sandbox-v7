package com.secsandbox.payroll;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Audit/export side of the payroll app.
 *
 * Every sink here is reached through a receiver whose simple class name maps to
 * more than one library in the catalog (`Logger` -> slf4j / log4j / j.u.l,
 * `EntityManager` -> jakarta / javax, `HttpClient` -> java.net.http / apache),
 * so the graph cannot attribute the call from the simple name alone.
 */
@Service
public class PayrollAuditService {

    private static final Logger log = LoggerFactory.getLogger(PayrollAuditService.class);

    private static final URI PAYROLL_EXPORT = URI.create("http://payroll-archive.internal/salaries");

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @PersistenceContext
    private EntityManager entityManager;

    // CWE-639: the caller names the record; no ownership check on the result.
    public Salary lookupSalary(Long id) {
        return entityManager.find(Salary.class, id);
    }

    // CWE-639: second lookup site — IDOR_LOOKUP is per-site, not grouped.
    public Salary lookupForAdjustment(Long employeeId) {
        Salary target = entityManager.find(Salary.class, employeeId);
        log.warn("adjustment requested for {} at {}", target.getEmployeeName(), target.getAmount());
        return target;
    }

    // CWE-312: salary amount written to the log in cleartext.
    public void auditPayout(Salary salary) {
        log.info("payout {} -> {}", salary.getEmployeeName(), salary.getAmount());
    }

    // CWE-312: failure path logs the same sensitive fields.
    public void auditFailure(Salary salary, Exception cause) {
        log.error("payout failed for {} amount {}", salary.getEmployeeName(), salary.getAmount(), cause);
    }

    // CWE-319: salary payload leaves the process over plaintext http.
    public int exportSalaries(String payload) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(PAYROLL_EXPORT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode();
    }
}
