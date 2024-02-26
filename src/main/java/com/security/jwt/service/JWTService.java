package com.security.jwt.service;

import com.security.jwt.model.USer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Service
public class JWTService {
    private final String SECRET_KEY="6dd0e869a7b9bd41cf00e4ee955659b317f5df4eb6e9222b32fbe261ee40208d";
    private Claims extractAllclaims(String token){
        return Jwts.parser().verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public <T> T extractClaims(String token, Function<Claims,T> resolver){
        Claims claims=extractAllclaims(token);
        return resolver.apply(claims);
    }
    public String extractUsername(String token){
        return extractClaims(token,Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails user){
        String username=extractUsername(token);
        return (username.equals(user.getUsername())) && !isTokenExpired(token);

    }

    public boolean isTokenExpired(String token){
        return extractExpirationTime(token).before(new Date());
    }

    private Date extractExpirationTime(String token) {
        return extractClaims(token,Claims::getExpiration);
    }

    public String generateToken(USer user)  {
        String token= Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSigninKey())
                .compact();
   return token;
    }
    private SecretKey getSigninKey(){
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
