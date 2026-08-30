package com.secsandbox.payroll;

import java.math.BigDecimal;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Salary {

    @Id
    private Long id;
    private String employeeName;
    private BigDecimal amount;

    public Long getId() { return id; }
    public String getEmployeeName() { return employeeName; }
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
}
