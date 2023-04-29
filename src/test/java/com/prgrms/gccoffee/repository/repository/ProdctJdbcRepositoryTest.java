package com.prgrms.gccoffee.repository.repository;

import com.prgrms.gccoffee.model.Category;
import com.prgrms.gccoffee.model.Product;
import com.prgrms.gccoffee.repository.ProductJdbcRepository;
import com.wix.mysql.EmbeddedMysql;
import com.wix.mysql.ScriptResolver;
import com.wix.mysql.config.Charset;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.*;
import static org.hamcrest.Matchers.*;

import static com.wix.mysql.EmbeddedMysql.anEmbeddedMysql;
import static com.wix.mysql.distribution.Version.*;
import static com.wix.mysql.config.MysqldConfig.*;


@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@ActiveProfiles("test") //application-test.yml 을 읽음
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // test 인스턴스: 클래스당 하나만 만들도록 설정.
class ProdctJdbcRepositoryTest {

    static EmbeddedMysql embeddedMysql;

    @BeforeAll
    static void setUp(){
        var config = aMysqldConfig(v5_7_latest)
                .withCharset(Charset.UTF8)
                .withPort(2215)
                .withUser("test", "test1234!")
                .withTimeZone("Asia/Seoul")
                .build();
        embeddedMysql = anEmbeddedMysql(config)
                .addSchema("test-order-mgmt", ScriptResolver.classPathScript("schema.sql"))
                .start();
    }

    @AfterAll
    static void cleanUp(){
        embeddedMysql.stop();
    }


    @Autowired
    ProductJdbcRepository repository;

    //static 으로 해줘야 매 test 마다 인스턴스가 새로 만들어지지 않음.
    //static 이 아니면 새로 인스턴스 생성됨, UUID 다름.
    //@TestInstance(TestInstance.LifeCycle.PER_TEST) 로 설정해도 ok.
    private static final Product newProduct = new Product(UUID.randomUUID(), "new-product", Category.COFFEE_BEAN_PACKAGE, 1000L);

    @Test
    @Order(1)
    @DisplayName("상품을 추가할 수 있다.")
    void testInsert(){
        repository.insert(newProduct);
        var all = repository.findAll();
        assertThat(all.isEmpty(), is(false));
    }

    @Test
    @Order(2)
    @DisplayName("상품을 이름으로 조회할 수 있다")
    void testFindByName(){
        var product = repository.findByName(newProduct.getProductName());
        assertThat(product.isEmpty(), is(false));
    }


    @Test
    @Order(3)
    @DisplayName("상품을 아이디로 조회할 수 있다")
    void testFindById(){
        var product = repository.findById(newProduct.getProductId());
        assertThat(product.isEmpty(), is(false));
    }


    @Test
    @Order(4)
    @DisplayName("상품을 카테고리으로 조회할 수 있다")
    void testFindByCategory(){
        var product = repository.findByCategory(newProduct.getCategory());
        assertThat(product.isEmpty(), is(false));
    }

    @Test
    @Order(5)
    @DisplayName("상품을 수정할 수 있다.")
    void testUpdate(){
        newProduct.setProductName("updated-product");
        repository.update(newProduct);

        var product = repository.findById(newProduct.getProductId());
        assertThat(product.isEmpty(), is(false));
        assertThat(product.get(), samePropertyValuesAs(newProduct));
    }

    @Test
    @Order(6)
    @DisplayName("상품을 전체 삭제한다.")
    void testDeleteAll(){
        repository.deleteAll();
        var all = repository.findAll();
        assertThat(all.isEmpty(), is(true));
    }


}