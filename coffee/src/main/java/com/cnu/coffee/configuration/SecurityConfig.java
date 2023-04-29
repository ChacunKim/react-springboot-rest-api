package com.cnu.coffee.configuration;

import com.cnu.coffee.jwt.Jwt;
import com.cnu.coffee.jwt.JwtAuthenticationFilter;
import com.cnu.coffee.jwt.JwtAuthenticationProvider;
import com.cnu.coffee.jwt.JwtSecurityContextRepository;
import com.cnu.coffee.member.MemberDetailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletResponse;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationContext applicationContext;
    private final JwtConfig jwtConfig;

    @Bean
    PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}

    @Bean
    WebSecurityCustomizer webSecurityCustomizer(){
        return (web -> web.ignoring().antMatchers(HttpMethod.POST, "/member")
                .antMatchers(HttpMethod.POST, "/login")
                .antMatchers(HttpMethod.GET, "/logout"));
    }

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
    Jwt jwt(){
        return new Jwt(
                jwtConfig.getIssuer(),
                jwtConfig.getClientSecret(),
                jwtConfig.getExpirySeconds()
        );
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider(Jwt jwt, MemberDetailService memberDetailService){
        return new JwtAuthenticationProvider(jwt, memberDetailService);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        Jwt jwt = applicationContext.getBean(Jwt.class);
        return new JwtAuthenticationFilter(jwtConfig.getHeader(), jwt);
    }

    public SecurityContextRepository securityContextRepository(){
        Jwt jwt = applicationContext.getBean(Jwt.class);
        return new JwtSecurityContextRepository(jwtConfig.getHeader(), jwt);
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
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
                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                    .and()
                .securityContext()
                    .securityContextRepository(securityContextRepository())
                    .and()

        ;
    return http.build();
    }
}
