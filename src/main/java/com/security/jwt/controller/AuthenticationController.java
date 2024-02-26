package com.security.jwt.controller;

import com.security.jwt.dto.AuthenticationResponse;
import com.security.jwt.model.USer;
import com.security.jwt.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }


    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody USer registerDTO){
        return ResponseEntity.ok(authenticationService.register(registerDTO));
    }
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody USer loginDTO){
        return ResponseEntity.ok(authenticationService.authenticate(loginDTO));
    }

}
