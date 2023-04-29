package com.cnu.coffee.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;

import java.util.Date;


public class Jwt {

    private final String issuer;

    private final String clientSecret;

    private final int expirySeconds;

    private final Algorithm algorithm;

    private final JWTVerifier jwtVerifier;

    public Jwt(String issuer, String clientSecret, int expirySeconds){
        this.issuer = issuer;
        this.clientSecret = clientSecret;
        this.expirySeconds = expirySeconds;
        this.algorithm = Algorithm.HMAC512(clientSecret);
        this.jwtVerifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
    }

    public String sign(Claims claims){
        Date now = new Date();
        JWTCreator.Builder builder = JWT.create();
        builder.withIssuer(issuer);
        builder.withIssuedAt(now);
        if(expirySeconds > 0){
            builder.withExpiresAt(new Date(now.getTime() + expirySeconds * 1_000L));
        }
        builder.withClaim("username", claims.username);
        builder.withArrayClaim("roles", claims.roles);
        return builder.sign(algorithm);
    }

    public Claims verify(String token) {
        return new Claims(jwtVerifier.verify(token));
    }

    static public class Claims{
        String username;
        String[] roles;
        Date issuedAt;
        Date expiredAt;

        private Claims(){}

        Claims(DecodedJWT decodedJWT){
            Claim username = decodedJWT.getClaim("username");
            if (!username.isNull()){
                this.username = username.asString();
            }

            Claim roles = decodedJWT.getClaim("roles");
            if (!roles.isNull()){
                this.roles = roles.asArray(String.class);
            }
            this.issuedAt = decodedJWT.getIssuedAt();
            this.expiredAt = decodedJWT.getExpiresAt();
        }

        public static Claims from(String username, String[] roles){
            Claims claims = new Claims();
            claims.username = username;
            claims.roles = roles;
            return claims;
        }

        long toTimeStamp(Date date){
            return date != null ? date.getTime() : -1;
        }

    }

}
