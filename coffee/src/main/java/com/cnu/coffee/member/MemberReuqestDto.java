package com.cnu.coffee.member;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class MemberReuqestDto {

    private String nickName;

    private String email;

    private String credential;

    private Role role;

}
