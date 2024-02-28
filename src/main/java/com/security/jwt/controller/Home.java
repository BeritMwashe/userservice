package com.security.jwt.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController

public class Home {
    @GetMapping("")
    public ResponseEntity<String> getBook() {
//        System.out.println();

        return new ResponseEntity<>("Access Token: " + "Created ", HttpStatus.ACCEPTED);
    }
//    @GetMapping("/token")
//    public String getToken(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
//        // Access the OAuth2 token
//        String accessToken = principal.getAttribute("access_token");
//
//        return "Access Token: " + accessToken;
//    }
}