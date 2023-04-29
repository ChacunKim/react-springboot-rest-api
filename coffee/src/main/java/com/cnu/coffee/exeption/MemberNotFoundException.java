package com.cnu.coffee.exeption;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class MemberNotFoundException extends RuntimeException{
    public MemberNotFoundException(String msg) {
        super(msg);
    }

    public MemberNotFoundException(RuntimeException e){
        super(e);
    }
}
