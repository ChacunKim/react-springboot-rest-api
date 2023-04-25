package com.cnu.coffee.product;

import com.cnu.coffee.exeption.ProductNotFoundException;
import com.cnu.coffee.product.domain.ProductResponseDto;
import com.cnu.coffee.product.domain.ProductRequestDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/product")
public class ProductController {

    @Autowired
    ProductService productService;

    @PostMapping("")
    public ProductResponseDto insertProduct(@RequestBody ProductRequestDto productRequestDTO){
        return productService.insertProduct(productRequestDTO);
    }

    @GetMapping("/all")
    public List<ProductResponseDto> getAllProducts(){
        return productService.findAllProducts();
    }

    @GetMapping("/{id}")
    public ProductResponseDto getProduct(@PathVariable("id") Long id) throws ProductNotFoundException {
        return productService.findById(id);
    }

    @PutMapping("/{id}")
    public ProductResponseDto update(@PathVariable("id") Long id, @RequestBody ProductRequestDto productRequestDTO)
            throws ProductNotFoundException {
        return productService.updateProduct(id, productRequestDTO);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable("id") Long id) throws ProductNotFoundException {
        productService.deleteProduct(id);
    }

    @DeleteMapping("/deleteAll")
    public void deleteAll(){
        productService.deleteAllProducts();
    }
}
