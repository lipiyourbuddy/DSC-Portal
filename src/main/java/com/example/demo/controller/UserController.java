package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.util.KeyToolUtil;

import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;


@Controller
public class UserController {

    @Autowired
    private UserRepository userRepository;
    
    @GetMapping("/")
    public String showHomePage() {
        return "home";
    }

    @GetMapping("/userlogin")
    public String showUserLoginForm() {
        return "userlogin";
    }

    @PostMapping("/userlogin")
    public String processUserLogin(@RequestParam String email, @RequestParam String phone, Model model) {
        User user = userRepository.findByEmail(email);
        if (user != null && user.getPhone().equals(phone)) {
            model.addAttribute("user", user);
            return "success"; // You can create a separate user dashboard if needed
        } else {
            model.addAttribute("error", "Invalid email or phone");
            return "userlogin";
        }
    }


    @GetMapping("/register")
    public String showForm(Model model) {
    	model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String submitForm(@ModelAttribute User user, Model model) {
        try {
            // Create DNAME string
            String dname = String.format("CN=%s, OU=%s, O=%s, C=%s",
                user.getFullName(), user.getOrganizationUnit(),
                user.getOrganization(), user.getCountry());

            // Output folder for DSC
            String outputDir = "src/main/resources/static/dscs";
            String dscPath = KeyToolUtil.generateDSC(
                user.getFullName().replaceAll("\\s+", "_"),
                user.getPassword(),
                dname,
                outputDir
            );

            user.setDscPath(dscPath);
            user.setAuthMode("OTP"); // default auth mode

            userRepository.save(user);

            model.addAttribute("user", user);
            return "userdashboard";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Failed to generate DSC.");
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
            // redirect to email OTP verification
            return "redirect:/send-otp";
        } else if ("DSC".equalsIgnoreCase(authMode)) {
            // redirect to DSC upload page
            return "redirect:/verify-dsc";
        } else {
            // authMode is NONE or NULL → direct to dashboard
            model.addAttribute("user", user);
            return "userdashboard";
        }
    }


}