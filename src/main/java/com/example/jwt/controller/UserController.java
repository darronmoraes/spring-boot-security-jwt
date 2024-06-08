package com.example.jwt.controller;

import com.example.jwt.entity.AuthRequest;
import com.example.jwt.entity.User;
import com.example.jwt.service.JwtService;
import com.example.jwt.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserInfoService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;


    @GetMapping("/welcome")
    public ResponseEntity<String> welcome() {
        return new ResponseEntity<>("Welcome! this endpoint is not secure.", HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<String> addUser(@RequestBody User userInput) {
        return new ResponseEntity<>(userService.saveUser(userInput), HttpStatus.CREATED);
    }

    @GetMapping("/users/profile-dummy")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String userProfile() {
        return "Welcome to user profile";
    }

    @GetMapping("/admin/profile-dummy")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminProfile() {
        return "Welcome to admin profile";
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginAuth(@RequestBody AuthRequest authRequest) {
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

        if (auth.isAuthenticated()) {
            return new ResponseEntity<>(jwtService.generateToken(authRequest.getUsername()), HttpStatus.ACCEPTED);
        } else {
            throw new UsernameNotFoundException("Invalid user request");
        }
    }
}
