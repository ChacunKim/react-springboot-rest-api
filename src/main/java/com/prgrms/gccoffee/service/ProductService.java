package com.prgrms.gccoffee.service;

import com.prgrms.gccoffee.model.Category;
import com.prgrms.gccoffee.model.Product;

import java.util.List;

public interface ProductService {

    List<Product> getProductsByCategory(Category category);

    List<Product> getAllProducts();

    Product createProduct(String productName, Category category, long price);

    Product createProduct(String productName, Category category, long price, String description);

}
