package com.cnu.coffee.jwt;

import com.cnu.coffee.member.LoginResponseDto;
import com.cnu.coffee.member.MemberDetailService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;

import static org.apache.logging.log4j.util.Strings.isNotEmpty;
import static org.springframework.util.TypeUtils.isAssignable;

@AllArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private Jwt jwt;

    @Autowired
    private MemberDetailService memberDetailService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
        return processUserAuthentication(
                String.valueOf(jwtAuthentication.getPrincipal()),
                jwtAuthentication.getCredentials()
        );
    }

    private Authentication processUserAuthentication(String principal, String credential) {
        try {
            LoginResponseDto loginResponseDto = memberDetailService.login(principal, credential);
            List<GrantedAuthority> authorities = loginResponseDto.getAuthorities();
            String token = getToken(loginResponseDto.getEmail(), authorities);
            JwtAuthenticationToken authenticated =
                    new JwtAuthenticationToken(new JwtAuthentication(token, loginResponseDto.getEmail()), null, authorities);
            authenticated.setDetails(loginResponseDto);
            return authenticated;
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(e.getMessage());
        } catch (DataAccessException e) {
            throw new AuthenticationServiceException(e.getMessage(), e);
        }
    }

    private String getToken(String username, List<GrantedAuthority> authorities) {
        String[] roles = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);
        return jwt.sign(Jwt.Claims.from(username, roles));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return isAssignable(JwtAuthenticationToken.class, authentication);
    }
}
