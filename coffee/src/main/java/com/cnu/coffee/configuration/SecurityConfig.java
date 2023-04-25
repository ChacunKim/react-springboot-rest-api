package com.cnu.coffee.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletResponse;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final ApplicationContext applicationContext;

    @Bean
    PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}

    AccessDeniedHandler accessDeniedHandler(){
        return (request, response, e) ->{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} id denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeRequests()
                .antMatchers(HttpMethod.POST, "/member").permitAll()
                .antMatchers(HttpMethod.GET, "/member/**").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.PUT, "/member").hasAnyRole("USER","ADMIN")
                .antMatchers(HttpMethod.DELETE, "/member").hasAnyRole("USER","ADMIN")
                .anyRequest().permitAll()
                    .and()
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                    .and()
                .csrf().disable()
        ;
    return http.build();
    }
}
