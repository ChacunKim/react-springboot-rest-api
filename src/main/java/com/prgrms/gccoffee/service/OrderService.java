package com.prgrms.gccoffee.service;

import com.prgrms.gccoffee.model.Email;
import com.prgrms.gccoffee.model.Order;
import com.prgrms.gccoffee.model.OrderItem;

import java.util.List;

public interface OrderService {
    Order createOrder(Email email, String address, String postcode, List<OrderItem> orderItems);
}
