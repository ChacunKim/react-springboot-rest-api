package com.cnu.coffee.member;

import com.cnu.coffee.exeption.MemberNotFoundException;
import com.cnu.coffee.jwt.JwtAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.cnu.coffee.jwt.JwtAuthentication.checkArgument;
import static org.apache.logging.log4j.util.Strings.isNotEmpty;

@Service
@RequiredArgsConstructor
public class MemberDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    private final PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (isNotEmpty(username)){
            Member member = memberRepository.findByEmail(username).orElseThrow(MemberNotFoundException::new);
            return new User(
                    member.getId().toString(),
                    member.getEmail(),
                    member.getAuthorities()
            );
        }else{
            throw new IllegalAccessError("Email must be provided");
        }
    }

    public LoginResponseDto login(String principal, String credential) {
        checkArgument(isNotEmpty(principal), "principal must be provided.");

        Member member = memberRepository.findByEmail(principal)
                .orElseThrow(() -> new MemberNotFoundException("Could not found user for " + principal));

        member.checkPassword(passwordEncoder, credential);

        return new LoginResponseDto(
                null,
                member.getEmail(),
                member.getRole().toString()
        );
    }

}
