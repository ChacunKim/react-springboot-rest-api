package com.prgrms.gccoffee.controller;

import com.prgrms.gccoffee.model.Category;

public record CreateProductRequest(String productName, Category category, long price, String description) {
}
