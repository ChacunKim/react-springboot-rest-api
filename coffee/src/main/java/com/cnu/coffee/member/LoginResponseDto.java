package com.cnu.coffee.member;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponseDto {
    private String token;
    private String email;
    private String role;
    public List<GrantedAuthority> getAuthorities(){
        return Collections.singletonList(
                new SimpleGrantedAuthority(role.toString())
        );
    }
}
