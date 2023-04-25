package com.cnu.coffee.member;

import org.springframework.beans.factory.annotation.Autowired;
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
}
