package com.cnu.coffee.member;

import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class MemberResponseDto {
    private UUID id;
    private String nickName;
    private String email;
}
