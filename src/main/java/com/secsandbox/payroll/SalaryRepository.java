package com.secsandbox.payroll;

import org.springframework.data.jpa.repository.JpaRepository;

// Spring Data repo — inherits findAll(), count(), saveAll() from CrudRepository.
public interface SalaryRepository extends JpaRepository<Salary, Long> {
}
