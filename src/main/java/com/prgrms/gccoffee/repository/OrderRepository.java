package com.prgrms.gccoffee.repository;

import com.prgrms.gccoffee.model.Order;

import java.util.Map;

public interface OrderRepository {
    Order insert(Order order);
}