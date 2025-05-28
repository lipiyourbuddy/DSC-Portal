package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/", "/register", "/logout", "/login", "/send-otp", "/verify-otp",
                    "/userlogin", "/download-dsc/**", "/update-auth", "/userlist",
                    "/css/**", "/js/**", "/images/**", "/userlogin", "/verify-dsc", "/user/send-otp", "/user/verify-otp"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(login -> login
                .loginPage("/login")
                .defaultSuccessUrl("/userlist", true)
                .permitAll()
            )
            .logout(logout -> logout.logoutSuccessUrl("/register"));

        return http.build();
    }
}
