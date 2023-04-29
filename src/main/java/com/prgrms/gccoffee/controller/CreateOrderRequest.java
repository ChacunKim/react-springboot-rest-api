package com.prgrms.gccoffee.controller;

import com.prgrms.gccoffee.model.OrderItem;

import java.util.List;

public record CreateOrderRequest(
        String email, String address, String postcode, List<OrderItem> orderItems
) {
}