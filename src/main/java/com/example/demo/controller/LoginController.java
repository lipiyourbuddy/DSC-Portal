package com.example.demo.controller;

import com.example.demo.dto.OtpLogin;
import com.example.demo.model.Admin;
import com.example.demo.model.User;
import com.example.demo.repository.AdminRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

@Controller
public class LoginController {

    @Autowired
    private AdminRepository adminRepo;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private EmailService emailService;

    // Temporary OTP store (email -> OTP)
    private Map<String, String> otpStore = new HashMap<>();

    
    @GetMapping("/login")
    public String showLoginPage(Model model) {
        model.addAttribute("otpLogin", new OtpLogin());
        return "login";
    }

    // Handle "Generate OTP" submission
    @PostMapping("/send-otp")
    public String sendOtp(@ModelAttribute OtpLogin otpLogin, Model model) {
        Admin admin = adminRepo.findByUsername(otpLogin.getUsername());

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        if (admin == null || !encoder.matches(otpLogin.getPassword(), admin.getPassword())
                || !admin.getEmail().equals(otpLogin.getEmail())) {
            model.addAttribute("error", "Invalid credentials");
            return "login";
        }

        // Generate and store OTP
        String generatedOtp = String.format("%06d", new Random().nextInt(999999));
        String normalizedEmail = admin.getEmail().trim().toLowerCase();
        otpStore.put(normalizedEmail, generatedOtp);

        otpStore.put(otpLogin.getEmail(), generatedOtp);

       
        emailService.sendOtp(otpLogin.getEmail(), generatedOtp);

        model.addAttribute("otpLogin", otpLogin);
        model.addAttribute("otpSent", true);
        
        return "login";
    }

    
    @PostMapping("/verify-otp")
    public String verifyOtp(@ModelAttribute OtpLogin otpLogin, Model model) {
        if (otpLogin.getEmail() == null || otpLogin.getOtp() == null) {
            model.addAttribute("error", "Email and OTP are required.");
            model.addAttribute("otpSent", true);
            model.addAttribute("otpLogin", otpLogin);
            return "login";
        }

        String email = otpLogin.getEmail().trim().toLowerCase();
        String correctOtp = otpStore.get(email);

        if (correctOtp != null && correctOtp.equals(otpLogin.getOtp().trim())) {
            List<User> users = (List<User>) userRepo.findAll();
            model.addAttribute("users", users);
            otpStore.remove(email);
            return "userlist";
        } else {
            model.addAttribute("error", "Invalid OTP");
            model.addAttribute("otpSent", true);
            model.addAttribute("otpLogin", otpLogin);
            
            System.out.println("Submitted Email: " + otpLogin.getEmail());
            System.out.println("Submitted OTP: " + otpLogin.getOtp());
            System.out.println("Expected OTP: " + correctOtp);

            return "login";
        }
    }

    
    @PostMapping("/update-auth")
    public String updateAuthModes(@RequestParam List<Long> userIds,
                                  @RequestParam Map<String, String> allParams,
                                  RedirectAttributes redirectAttributes) {

        for (Long userId : userIds) {
            String paramName = "authMode_" + userId;
            String selectedMode = allParams.getOrDefault(paramName, "NONE");

            userRepo.findById(userId).ifPresent(user -> {
                if ("NONE".equalsIgnoreCase(selectedMode)) {
                    user.setAuthMode(null); 
                } else {
                    user.setAuthMode(selectedMode); // OTP or DSC
                }
                userRepo.save(user);
            });
        }

        redirectAttributes.addFlashAttribute("success", true);
        return "redirect:/admin/userlist";
    }

    
    
    
    @GetMapping("/admin/download-public-key/{userId}")
    public ResponseEntity<Resource> downloadPublicKey(@PathVariable Long userId) {
        Optional<User> optionalUser = userRepo.findById(userId);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = optionalUser.get();

        try {
            byte[] keyBytes = Base64.getDecoder().decode(user.getPublicKey());
            Path tempFile = Files.createTempFile("publicKey-", ".pem");

            String pemFormatted = "-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(keyBytes).replaceAll("(.{64})", "$1\n") +
                    "\n-----END PUBLIC KEY-----\n";

            Files.write(tempFile, pemFormatted.getBytes(StandardCharsets.UTF_8));

            Resource resource = new FileSystemResource(tempFile.toFile());

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + user.getFullName() + "_public_key.pem")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(resource);

        } catch (IOException e) {
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/admin/userlist")
    public String getUserList(@RequestParam(name = "filter", required = false, defaultValue = "ALL") String filter,
                              Model model) {
        List<User> users;

        switch (filter.toUpperCase()) {
            case "DSC":
                users = userRepo.findByAuthMode("DSC");
                break;
            case "OTP":
                users = userRepo.findByAuthMode("OTP");
                break;
            case "NONE":
                users = userRepo.findByAuthModeIsNull(); 
                break;
            default:
                users = (List<User>) userRepo.findAll();
        }

        model.addAttribute("users", users);
        model.addAttribute("filter", filter.toUpperCase());
        return "userlist";
    }



    // Optional logout redirect
    @GetMapping("/logout")
    public String logout() {
        return "redirect:/home";
    }
}
