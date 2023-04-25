package com.cnu.coffee.member;

import com.cnu.coffee.product.domain.ProductResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class MemberControllerTest {

    private static final Logger logger = LoggerFactory.getLogger(MemberControllerTest.class);

    @Autowired
    MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("유저 등록")
    void testRegister() throws Exception {
        MemberReuqestDto requestDto = new MemberReuqestDto();
        requestDto.setNickName("심심한 바다코끼리");
        requestDto.setEmail("sample@abc.com");
        requestDto.setRole(Role.USER);
        requestDto.setCredential("test1234@#");

        MvcResult result = mockMvc.perform(post("/member")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        MemberResponseDto responseDto = objectMapper.readValue(content, MemberResponseDto.class);
        logger.info("inserted product -> {}", responseDto);
    }

}