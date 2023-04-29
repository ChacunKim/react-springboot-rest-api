package com.cnu.coffee.member;

import com.cnu.coffee.jwt.JwtAuthentication;
import com.cnu.coffee.jwt.JwtAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/member")
public class MemberController {

    @Autowired
    private MemberService memberService;

    @PostMapping("")
    public MemberResponseDto registerMember(@RequestBody MemberReuqestDto memberReuqestDto){
        return memberService.register(memberReuqestDto);
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequestDto loginRequestDto){
        JwtAuthenticationToken authToken = new JwtAuthenticationToken(loginRequestDto.getEmail(), loginRequestDto.getMemberSecret());
        Authentication resultToken = memberService.authenticate(authToken);
        JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
        JwtAuthentication principal = (JwtAuthentication) authenticated.getPrincipal();
        return principal.token;
    }
}
