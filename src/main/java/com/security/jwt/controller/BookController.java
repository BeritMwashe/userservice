package com.security.jwt.controller;

import com.security.jwt.dto.AuthenticationResponse;
import com.security.jwt.model.USer;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/lists")
public class BookController {
    @GetMapping("/books")
    public ResponseEntity<String> getBook(){
        return new ResponseEntity<>("There are several books", HttpStatus.ACCEPTED);
    }
    @GetMapping("/premium_books")
    public ResponseEntity<String> getBookForAdmins(){
        return new ResponseEntity<>("There are several books For Premium uses", HttpStatus.ACCEPTED);
    }
    @PostMapping("/home")
    public ResponseEntity<String> home(@RequestBody USer loginDTO){
        return ResponseEntity.ok("This is home");
    }
    @PostMapping("/secured")
    public ResponseEntity<String> secured(@RequestBody USer loginDTO){
        return ResponseEntity.ok("This is a secured login home");
    }
}
