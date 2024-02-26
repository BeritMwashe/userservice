package com.security.jwt.service;

import com.security.jwt.dto.AuthenticationResponse;
import com.security.jwt.model.USer;
import com.security.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }


    public AuthenticationResponse register(USer request){
        USer user=new USer();
        user.setFirstName(request.getFirstName());
        user.setUserName(request.getUsername());
        user.setLastName(request.getLastName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        user=userRepository.save(user);

        String token= jwtService.generateToken(user);
        return new AuthenticationResponse(token);



    }
    public AuthenticationResponse authenticate(USer request){
       authenticationManager.authenticate(
               new UsernamePasswordAuthenticationToken(
                       request.getUsername(),
                       request.getPassword()
               )
       );
    USer user=userRepository.findByUserName(request.getUsername()).orElseThrow();
    String token= jwtService.generateToken(user);
    return new AuthenticationResponse(token);
    }
}
