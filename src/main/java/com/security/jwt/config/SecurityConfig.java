package com.security.jwt.config;


import com.security.jwt.exceptions.CustomAccessDeniedHandler;
import com.security.jwt.filter.JwtAuthenticationFilter;
import com.security.jwt.repository.UserRepository;
import com.security.jwt.service.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity

public class SecurityConfig {
    private final UserDetailsService userDetailsService;

    private final CustomAccessDeniedHandler accessDeniedHandler;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final UserRepository userRepository;

    public SecurityConfig(UserDetailsService userDetailsService, CustomAccessDeniedHandler accessDeniedHandler, JwtAuthenticationFilter jwtAuthenticationFilter, UserRepository userRepository) {
        this.userDetailsService = userDetailsService;
        this.accessDeniedHandler = accessDeniedHandler;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userRepository = userRepository;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{


        return http

                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(
                        req->
                                req.requestMatchers("/auth/login/**","/auth/register/**","/lists/home/**","/").permitAll()
                                .requestMatchers("/lists/premium_books/**").hasAnyAuthority("ADMIN")
//                                        .requestMatchers("/").hasAnyAuthority("ADMIN","USER")
                                        .requestMatchers("/add_clothes/**").hasAnyAuthority("ADMIN","SUPERVISOR")
                                .anyRequest()
                        .authenticated()
                        )


                .userDetailsService(userDetailsService)
                .exceptionHandling(e->
                        e.accessDeniedHandler(accessDeniedHandler)
                                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
//                .oauth2Login(Customizer.withDefaults())
//                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//                .oauth2Login((oauth2Login) -> oauth2Login
//                        .userInfoEndpoint((userInfo) -> userInfo
//                                .userAuthoritiesMapper(grantedAuthoritiesMapper())
//                                .oidcUserService(googleUserService) )
//                       )
                .logout(l -> l
                        .logoutSuccessUrl("/").permitAll()
                )

                .build();

    }

    @Bean
    @Order(1)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        Set<String> googleScopes = new HashSet<>();
        googleScopes.add("https://www.googleapis.com/auth/userinfo.email");
        googleScopes.add("https://www.googleapis.com/auth/userinfo.profile");
        googleScopes.add("https://www.googleapis.com/auth/user.phonenumbers.read");

        OidcUserService googleUserService = new OidcUserService();
        googleUserService.setAccessibleScopes(googleScopes);

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .oauth2Login(oauthLogin -> oauthLogin.userInfoEndpoint(userInfoEndpointConfig ->
                        userInfoEndpointConfig.oidcUserService(googleUserService)));
        return http.build();
    }
//        http
//                .authorizeHttpRequests((authorize) -> authorize
//                        .anyRequest().authenticated()
//                )
////                .oauth2Login(Customizer.withDefaults());
//         .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));



    private GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach((authority) -> {
                GrantedAuthority mappedAuthority;

                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority userAuthority = (OidcUserAuthority) authority;
                    mappedAuthority = new OidcUserAuthority(
                            "ROLE_USER", userAuthority.getIdToken(), userAuthority.getUserInfo());
                } else if (authority instanceof OAuth2UserAuthority) {
                    OAuth2UserAuthority userAuthority = (OAuth2UserAuthority) authority;
                    mappedAuthority = new OAuth2UserAuthority(
                            "ROLE_USER", userAuthority.getAttributes());
                } else {
                    mappedAuthority = authority;
                }

                mappedAuthorities.add(mappedAuthority);
            });

            return mappedAuthorities;
        };
    }



    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
