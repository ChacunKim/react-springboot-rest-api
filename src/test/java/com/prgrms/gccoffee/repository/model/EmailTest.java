package com.prgrms.gccoffee.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EmailTest {

    @Test
    @DisplayName("이메일 주소 검증1: 잘못된 이메일 주소 입력")
    public void testInvalidEmail(){
        assertThrows(IllegalArgumentException.class, () ->{
            var email = new Email("accc");
        });
    }

    @Test
    @DisplayName("이메일 주소 검증2: 올바른 이메일 주소 입력")
    public void testValidEmali(){
        var email = new Email("hello@gmail.com");
//        assertTrue(email.getAddress().equals("hello@gmail.com"));
        assertEquals("hello@gmail.com", email.getAddress());
    }


    @Test
    @DisplayName("같은 이메일 판정 확인")
    public void testEqualEmali(){
        var email = new Email("hello@gmail.com");
        var email2 = new Email("hello@gmail.com");
//        assertTrue(email.equals(email2))//equals: hello@gmail.com 같은 이메일이면 true 반환되는지 확인
        assertEquals(email, email2);
    }


}