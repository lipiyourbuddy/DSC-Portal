package com.example.demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.demo.model.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}
