package com.cnu.coffee.member;

import com.cnu.coffee.jwt.JwtAuthenticationToken;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class MemberService {

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    public MemberResponseDto convertEntityToDto(Member entity){
        MemberResponseDto dto = new MemberResponseDto();
        BeanUtils.copyProperties(entity, dto);
        return dto;
    }

    public MemberResponseDto register(MemberReuqestDto memberReuqestDto) {
        Member member = Member.builder()
                .email(memberReuqestDto.getEmail())
                .nickName(memberReuqestDto.getNickName())
                .role(memberReuqestDto.getRole())
                .memberSecret(passwordEncoder.encode(memberReuqestDto.getCredential()))
                .registeredDate(LocalDateTime.now())
                .modifiedDate(LocalDateTime.now())
                .build();
        Member saved = memberRepository.save(member);
        return convertEntityToDto(saved);
    }

    public Authentication authenticate(JwtAuthenticationToken authToken) {
        Authentication authenticate = authenticationManager.authenticate(authToken);
        return authenticate;
    }
}
