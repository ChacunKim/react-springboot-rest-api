package com.cnu.coffee.member;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class MemberService {
    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
                .credential(passwordEncoder.encode(memberReuqestDto.getCredential()))
                .registeredDate(LocalDateTime.now())
                .modifiedDate(LocalDateTime.now())
                .build();
        Member saved = memberRepository.save(member);
        return convertEntityToDto(saved);
    }
}
