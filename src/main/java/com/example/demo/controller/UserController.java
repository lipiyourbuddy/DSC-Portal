package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.util.KeyToolUtil;


import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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

/*    @PostMapping("/userlogin")
    public String processUserLogin(@RequestParam String email, @RequestParam String phone, Model model) {
        User user = userRepository.findByEmail(email);
        if (user != null && user.getPhone().equals(phone)) {
            model.addAttribute("user", user);
            return "success"; // You can create a separate user dashboard if needed
        } else {
            model.addAttribute("error", "Invalid email or phone");
            return "userlogin";
        }
    }*/


    @GetMapping("/register")
    public String showForm(Model model) {
    	model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String submitForm(@ModelAttribute User user, Model model) {
        try {
            String dname = String.format("CN=%s, OU=%s, O=%s, C=%s",
                user.getFullName(), user.getOrganizationUnit(),
                user.getOrganization(), user.getCountry());

            String outputDir = "src/main/resources/static/dscs";

            String dscPath = KeyToolUtil.generateDSC(
                user.getFullName().replaceAll("\\s+", "_"),
                user.getPassword(),
                dname,
                outputDir
            );

            user.setDscPath(dscPath);
            user.setAuthMode("OTP"); //default
            userRepository.save(user);
            
            System.out.println("Step 1: Generating DSC...");
            System.out.println("Step 2: Saving user...");
            System.out.println("Step 3: Returning dashboard...");


            model.addAttribute("user", user);
            return "userdashboard";  

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
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
            message.setFrom("youremail@gmail.com"); // must match configured email
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
    public String verifyDsc(@RequestParam("dscFile") MultipartFile uploadedFile,
                            HttpSession session,
                            Model model) throws IOException {
        User user = (User) session.getAttribute("loggedInUser");
        if (user == null) return "redirect:/userlogin";

        Path originalPath = Paths.get(user.getDscPath()).toAbsolutePath();

        // Save uploaded DSC temporarily
        Path uploadedPath = Paths.get("temp", uploadedFile.getOriginalFilename());
        Files.createDirectories(uploadedPath.getParent());
        Files.copy(uploadedFile.getInputStream(), uploadedPath, StandardCopyOption.REPLACE_EXISTING);

        // Compare contents byte-by-byte
        boolean match = Files.mismatch(originalPath, uploadedPath) == -1;

        // Delete temp file
        Files.deleteIfExists(uploadedPath);

        if (match) {
        	model.addAttribute("user", user);
        	return "userdashboard";

        } else {
            model.addAttribute("error", "DSC does not match.");
            return "verify-dsc";
        }
    }




}