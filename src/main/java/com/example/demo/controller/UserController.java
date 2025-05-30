package com.example.demo.controller;

import com.example.demo.model.User;
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

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Random;

@Controller
public class UserController {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;

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
                               HttpSession session) throws Exception {
        
        String savePath = "C:/Users/C22684/eclipse-workspace/springemployee_project6/src/main/resources/static/publickeys/" + file.getOriginalFilename();
        Path path = Paths.get(savePath);
        Files.createDirectories(path.getParent());
        file.transferTo(path.toFile());

        System.out.println("File saved\n\n");

        user.setDscPath("/publickeys/" + file.getOriginalFilename());

        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path.toFile())) {
            ks.load(fis, user.getPassword().toCharArray());
        }

        String alias = ks.aliases().nextElement();
        Certificate cert = ks.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        user.setPublicKey(publicKeyBase64);

        userRepository.save(user);

        // 🔐 Set user in session so dashboard works
        session.setAttribute("loggedInUser", user);

        return "redirect:/userdashboard";
    }



    @PostMapping("/userlogin")
    public String handleUserLogin(@RequestParam String fullName,
                                  @RequestParam String password,
                                  Model model,
                                  HttpSession session) {

        User user = userRepository.findByFullName(fullName);

        if (user == null || !user.getPassword().equals(password)) {
            model.addAttribute("error", "Invalid credentials");
            return "userlogin";
        }

        session.setAttribute("loggedInUser", user);

        String authMode = user.getAuthMode();

        if ("OTP".equalsIgnoreCase(authMode)) {
            return "redirect:/user/send-otp";
        } else if ("DSC".equalsIgnoreCase(authMode)) {
            return "redirect:/verify-dsc";
        } else {
            model.addAttribute("user", user);
            return "userdashboard";
        }
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
                            Model model) throws Exception {

        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/userlogin";

        // Save uploaded DSC temporarily
        Path tempFile = Files.createTempFile("uploaded-", ".jks");
        dscFile.transferTo(tempFile.toFile());

        boolean match;

        try (FileInputStream fis = new FileInputStream(tempFile.toFile())) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(fis, keyPassword.toCharArray());

            String alias = ks.aliases().nextElement();
            Certificate cert = ks.getCertificate(alias);
            PublicKey uploadedKey = cert.getPublicKey();
            String uploadedBase64 = Base64.getEncoder().encodeToString(uploadedKey.getEncoded());

            match = uploadedBase64.equals(user.getPublicKey());
        } catch (Exception e) {
            model.addAttribute("error", "Invalid or corrupt keystore.");
            return "verify-dsc";
        } finally {
            Files.deleteIfExists(tempFile);
        }

        if (match) {
            model.addAttribute("user", user);
            return "userdashboard";
        } else {
            model.addAttribute("error", "DSC public key does not match.");
            return "verify-dsc";
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
