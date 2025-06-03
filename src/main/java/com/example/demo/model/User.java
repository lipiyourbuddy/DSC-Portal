package com.example.demo.model;

import java.time.LocalDateTime;

import jakarta.persistence.*;

@Entity
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "organization")
    private String organization;
    
    @Column(name = "organization_unit")
    private String organizationUnit;
    
    @Column(name = "country")
    private String country;
    
    @Column(name = "password")
    private String password;

    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey; // Base64-encoded public key string

    @Column(name = "dsc_path")
    private String dscPath; // Path to uploaded public key file (optional for audit)

    @Column(name = "auth_mode")
    private String authMode = "OTP"; // default
    
    @Column(name = "last_login")
    private LocalDateTime lastLogin;
    
    // Getters and setters
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }
    
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getDscPath() {
        return dscPath;
    }
    public void setDscPath(String dscPath) {
        this.dscPath = dscPath;
    }
    
    public String getAuthMode() {
        return authMode;
    }
    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }
    
    public String getOrganizationUnit() {
        return organizationUnit;
    }
    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }
    
    public String getCountry() {
        return country;
    }
    public void setCountry(String country) {
        this.country = country;
    }
    
    public String getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
    
    public LocalDateTime getLastLogin() {
        return lastLogin;
    }
    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }
    
}