package com.security.jwt.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController

public class Home {
    @GetMapping("")
    public Map<String, Object> getUser(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return oAuth2User.getAttributes();

    }
//    @GetMapping("")
//    public ResponseEntity<String> getBook() {
////        System.out.println();
//
//        return new ResponseEntity<>("Access Token: " + "Created ", HttpStatus.ACCEPTED);
//    }
//    @GetMapping("/token")
//    public String getToken(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
//        // Access the OAuth2 token
//        String accessToken = principal.getAttribute("access_token");
//
//        return "Access Token: " + accessToken;
//    }
}