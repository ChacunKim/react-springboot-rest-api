package com.cnu.coffee.configuration;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Getter
@Component
public class JwtConfig {

//    @Value("${auth0.audience}")
//    private String audience;

    private String header = HttpHeaders.AUTHORIZATION;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.client-secret}")
    private String clientSecret;

    @Value("${jwt.expiry-seconds}")
    private int expirySeconds;
}
