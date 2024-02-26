package com.security.jwt.filter;
import com.security.jwt.service.JWTService;
import com.security.jwt.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;

    private final UserDetailsService userDetails;

        public JwtAuthenticationFilter(JWTService jwtService, UserDetailsService userDetails) {
            this.jwtService = jwtService;
            this.userDetails = userDetails;
        }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException,
            IOException {
        String authHeader=request.getHeader("Authorization");
        if(authHeader ==null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String token=authHeader.substring(7);

        String username= jwtService.extractUsername(token);



        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
            UserDetails uDetails = userDetails.loadUserByUsername(username);


            if (jwtService.isValid(token, uDetails)) {

             UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(uDetails, null, uDetails.getAuthorities());
           authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }

        }
        filterChain.doFilter(request,response);

    }
}
