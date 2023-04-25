package com.cnu.coffee.product;

import com.cnu.coffee.product.domain.Category;
import com.cnu.coffee.product.domain.ProductRequestDto;
import com.cnu.coffee.product.domain.ProductResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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

import java.util.Optional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ProductControllerTest {

    private static final Logger logger = LoggerFactory.getLogger(ProductControllerTest.class);

    @Autowired
    MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ProductService productService;

    ProductResponseDto product;


    @BeforeEach
    void setUp(){
        ProductRequestDto productRequestDTO = ProductRequestDto.builder()
                .productName("setup-product")
                .category(Category.COFFEE_DRIP)
                .price(1000)
                .description(Optional.of(""))
                .build();

        this.product = productService.insertProduct(productRequestDTO);
        logger.info("setUp: inserted Product -> {}", product);

    }

    @AfterEach
    void tearDown(){
        try{
            productService.deleteProduct(product.getId());
        }catch (RuntimeException e){
            logger.info("no such product -> id: {}", product.getId());
        }
    }

    @Test
    @DisplayName("상품 등록")
    void testInsert() throws Exception {
        ProductRequestDto productRequestDTO = ProductRequestDto.builder()
                .productName("test-coffee-product")
                .category(Category.COFFEE_BEAN)
                .price(1000)
                .description(Optional.of(""))
                .build();


        MvcResult result = mockMvc.perform(post("/product")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(productRequestDTO)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        ProductResponseDto productResponseDto = objectMapper.readValue(content, ProductResponseDto.class);
        logger.info("inserted product -> {}", productResponseDto);
    }

    @Test
    @DisplayName("상품 조회: 단건조회")
    void testFind() throws Exception {
        mockMvc.perform(get("/product/{id}", product.getId().toString()))
                .andExpect(status().isOk())
                .andDo(print());

    }

    @Test
    @DisplayName("상품 조회: 전체 조회")
    void testFindAll() throws Exception {
        ProductRequestDto productRequestDTO = ProductRequestDto.builder()
                .productName("test-coffee-product")
                .category(Category.COLD_BREW)
                .price(2000)
                .description(Optional.of(""))
                .build();

        productService.insertProduct(productRequestDTO);


        mockMvc.perform(get("/product/all"))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    @DisplayName("상품 수정")
    void testUpdate() throws Exception{
        ProductRequestDto productRequestDto = ProductRequestDto.builder()
                .productName("updated-coffee-product")
                .category(Category.COFFEE_INSTANT)
                .price(1500)
                .description(Optional.of("맛있는 커피 😊"))
                .build();

        MvcResult result = mockMvc.perform(put("/product/{id}", product.getId().toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(productRequestDto)))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();

        String content = result.getResponse().getContentAsString();
        product = objectMapper.readValue(content, ProductResponseDto.class);

        logger.info("updated Product -> {}", product);
    }


    @Test
    @DisplayName("상품 삭제")
    void testDelete() throws Exception{
        ProductRequestDto productRequestDto = ProductRequestDto.builder()
                .productName("coffee-product-for-delete")
                .category(Category.COFFEE_INSTANT)
                .price(1500)
                .description(Optional.of("삭제할 커피 상품"))
                .build();

        ProductResponseDto productResponseDto = productService.insertProduct(productRequestDto);

        mockMvc.perform(delete("/product/{id}", productResponseDto.getId().toString()))
                .andExpect(status().isOk())
                .andDo(print());
    }

    @Test
    @DisplayName("상품 전체 삭제")
    void testDeleteAll() throws Exception {
        ProductRequestDto productRequestDTO = ProductRequestDto.builder()
                .productName("test-coffee-product")
                .category(Category.COLD_BREW)
                .price(2000)
                .description(Optional.of(""))
                .build();
        productService.insertProduct(productRequestDTO);

        logger.info("before delete all -> {}", productService.findAllProducts());

        mockMvc.perform(delete("/product/deleteAll"))
                .andExpect(status().isOk())
                .andDo(print());

        logger.info("after delete all -> {}", productService.findAllProducts());
    }
}