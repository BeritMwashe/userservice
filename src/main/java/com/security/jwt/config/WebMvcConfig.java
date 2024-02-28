package com.security.jwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public interface WebMvcConfig extends WebMvcConfigurer {
    @Override

    public default void addCorsMappings(CorsRegistry registry){
        long MAX_AGE_SECS=3600;
        registry
                .addMapping("/**")
                .allowedOrigins("http://localhost:8181")
                .allowedMethods("HEAD","OPTIONS","GET","POST","PATCH","DELETE")
                .allowedHeaders("Authorization","Cache-Control","Content-Type")
                .maxAge(MAX_AGE_SECS);

    }
}

