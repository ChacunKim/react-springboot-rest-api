package com.cnu.coffee.jwt;

import ch.qos.logback.core.encoder.EchoEncoder;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;

import static org.apache.logging.log4j.util.Strings.isNotEmpty;


@Slf4j
public class JwtAuthentication {
    public final String token;
    public final String username;

    public JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided.");
        checkArgument(isNotEmpty(username), "username must be provided.");
        this.token = token;
        this.username = username;
    }

    public static void checkArgument(boolean expression, String errorMessage) {
        if (!expression) {
            throw new IllegalArgumentException(errorMessage);
        }
    }
}
