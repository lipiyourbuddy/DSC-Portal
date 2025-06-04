package com.example.demo.controller;

import com.example.demo.model.AuditLog;
import com.example.demo.model.User;
import com.example.demo.repository.AuditLogRepository;
import com.example.demo.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.chrono.ChronoLocalDate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;


import java.time.LocalDate;

@Controller
public class UserController {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AuditLogRepository auditLogRepo;

    @GetMapping("/home")
    public String showHomePage() {
        return "home";
    }

    @GetMapping("/userlogin")
    public String showUserLoginForm() {
        return "userlogin";
    }

    @GetMapping("/register")
    public String showForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user,
                               @RequestParam("publicKeyFile") MultipartFile file,
                               Model model,
                               HttpSession session,
                               RedirectAttributes redirectAttributes) throws Exception {

        
        String uploadDir = "C:/dsc-uploads/publickeys/";
        Files.createDirectories(Paths.get(uploadDir));

        String savePath = uploadDir + file.getOriginalFilename();
        Path path = Paths.get(savePath);
        file.transferTo(path.toFile());

        user.setDscPath("/publickeys/" + file.getOriginalFilename());

        
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            ks.load(fis, user.getPassword().toCharArray());
        }

        String alias = ks.aliases().nextElement();
        Certificate cert = ks.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        X509Certificate x509Cert = (X509Certificate) cert;

        
        String subjectDN = x509Cert.getSubjectX500Principal().getName();
        String cn = null;
        for (String part : subjectDN.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                cn = part.substring(3).trim();
                break;
            }
        }

        if (cn == null || !cn.equalsIgnoreCase(user.getFullName().trim())) {
            model.addAttribute("error", "DSC CN mismatch: Certificate does not belong to the entered user name.");
            return "register";
        }

        
        LocalDate expiryDate = x509Cert.getNotAfter().toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDate();

        if (LocalDate.now().isAfter(expiryDate)) {
            model.addAttribute("error", "DSC Invalid: Certificate has expired.");
            return "register";
        }

        
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        user.setPublicKey(publicKeyBase64);
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        session.setAttribute("loggedInUser", user);

        
        redirectAttributes.addFlashAttribute("subject", x509Cert.getSubjectX500Principal().getName());
        redirectAttributes.addFlashAttribute("issuer", x509Cert.getIssuerX500Principal().getName());
        redirectAttributes.addFlashAttribute("validFrom", x509Cert.getNotBefore());
        redirectAttributes.addFlashAttribute("validTo", x509Cert.getNotAfter());
        redirectAttributes.addFlashAttribute("serialNumber", x509Cert.getSerialNumber().toString());

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(x509Cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02X:", b));
            String fingerprint = sb.substring(0, sb.length() - 1);
            redirectAttributes.addFlashAttribute("fingerprint", fingerprint);
        } catch (Exception e) {
            System.out.println("SHA-256 generation failed: " + e.getMessage());
        }

        return "redirect:/userdashboard";
    }





    @PostMapping("/userlogin")
    public String handleUserLogin(@RequestParam String fullName,
                                  @RequestParam String password,
                                  Model model,
                                  HttpSession session) {

        User user = userRepository.findByFullName(fullName);
        boolean success = false;

        if (user != null && user.getPassword().equals(password)) {
            success = true;
            session.setAttribute("loggedInUser", user);
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            String authMode = user.getAuthMode();

            
            if ("OTP".equalsIgnoreCase(authMode)) {
                return "redirect:/user/send-otp";
            } else if ("DSC".equalsIgnoreCase(authMode)) {
                return "redirect:/verify-dsc";
            } else {
            	// ✅ Audit log for successful login
                AuditLog log = new AuditLog();
                log.setUsername(fullName);
                log.setMethod("PASSWORD");
                log.setSuccess(false);
                log.setTimeStamp(LocalDateTime.now());
                auditLogRepo.save(log);

                model.addAttribute("user", user);
                return "userdashboard";
            }
        }
        
        /*
        // ❌ Audit log for failed login
        AuditLog log = new AuditLog();
        log.setUsername(fullName);
        log.setMethod("PASSWORD");
        log.setSuccess(false);
        log.setTimeStamp(LocalDateTime.now());
        auditLogRepo.save(log);
        */

        model.addAttribute("error", "Invalid credentials");
        return "userlogin";
    }


    @GetMapping("/user/send-otp")
    public String sendOtpToUser(HttpSession session, Model model) {
        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/userlogin";

        String otp = String.valueOf(new Random().nextInt(900000) + 100000);
        session.setAttribute("userOtp", otp);

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(user.getEmail());
            message.setSubject("Your OTP for Login");
            message.setText("Your OTP is: " + otp);
            message.setFrom("youremail@gmail.com"); // change to your actual email
            mailSender.send(message);

            model.addAttribute("info", "OTP sent to your email.");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to send OTP: " + e.getMessage());
            return "userlogin";
        }

        return "user-otp";
    }

    @PostMapping("/user/verify-otp")
    public String verifyUserOtp(@RequestParam String otp,
                                HttpSession session,
                                Model model) {
        String sessionOtp = (String) session.getAttribute("userOtp");
        User user = (User) session.getAttribute("loggedInUser");

        if (user == null) return "redirect:/userlogin";

        if (sessionOtp != null && sessionOtp.equals(otp)) {
            model.addAttribute("user", user);
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            
         // Save audit log
            AuditLog log = new AuditLog();
            log.setUsername(user.getFullName());
            log.setMethod("OTP");
            log.setSuccess(false);
            log.setTimeStamp(LocalDateTime.now());
            auditLogRepo.save(log);
            return "userdashboard";
        } else {
            model.addAttribute("error", "Invalid OTP. Try again.");
            return "user-otp";
        }
    }

    @GetMapping("/verify-dsc")
    public String showDscUploadPage(HttpSession session) {
        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/userlogin";
        return "verify-dsc";
    }
    
    

    @PostMapping("/verify-dsc")
    public String verifyDsc(@RequestParam MultipartFile dscFile,
                            @RequestParam String keyPassword,
                            HttpSession session,
                            Model model) {
        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/userlogin";

        Path tempFile = null;
        boolean success = false;

        try {
            // Save uploaded DSC temporarily
            tempFile = Files.createTempFile("uploaded-", ".jks");
            dscFile.transferTo(tempFile.toFile());

            // Load keystore and keys
            KeyStore ks = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(tempFile.toFile())) {
                ks.load(fis, keyPassword.toCharArray());
            }

            String alias = ks.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
            Certificate cert = ks.getCertificate(alias);

            // Sign challenge
            byte[] challenge = "verify-dsc-authentication".getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signatureBytes = signer.sign();

            // Verify using stored public key
            byte[] pubKeyBytes = Base64.getDecoder().decode(user.getPublicKey());
            PublicKey publicKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pubKeyBytes));
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            success = verifier.verify(signatureBytes);

            if (!success) {
                model.addAttribute("error", "DSC verification failed: signature mismatch.");
                return "verify-dsc";
            }

            // Extract certificate info
            if (cert instanceof X509Certificate x509Cert) {
                model.addAttribute("subject", x509Cert.getSubjectX500Principal().getName());
                model.addAttribute("issuer", x509Cert.getIssuerX500Principal().getName());
                model.addAttribute("validFrom", x509Cert.getNotBefore());
                model.addAttribute("validTo", x509Cert.getNotAfter());
                model.addAttribute("serialNumber", x509Cert.getSerialNumber().toString());

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(x509Cert.getEncoded());
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) sb.append(String.format("%02X:", b));
                String fingerprint = sb.substring(0, sb.length() - 1);
                model.addAttribute("fingerprint", fingerprint);
            }

            // Update user and show dashboard
            model.addAttribute("user", user);
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            return "userdashboard";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Verification failed: " + e.getMessage());
            return "verify-dsc";
        } finally {
            // Save audit log
            AuditLog log = new AuditLog();
            log.setUsername(user.getFullName());
            log.setMethod("DSC");
            log.setSuccess(false);
            log.setTimeStamp(LocalDateTime.now());
            auditLogRepo.save(log);

            // Delete temp file
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {}
            }
        }
    }


    @GetMapping("/download-dsc/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> downloadDSC(@PathVariable String filename) throws IOException {
        Path filePath = Paths.get("src/main/resources/static/dscs").resolve(filename).normalize();
        Resource resource = new UrlResource(filePath.toUri());

        if (!resource.exists()) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                .body(resource);
    }
    
    @GetMapping("/userdashboard")
    public String showUserDashboard(HttpSession session, Model model) {
        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) {
            return "redirect:/userlogin";
        }
        model.addAttribute("user", user);
        return "userdashboard";
    }

}
