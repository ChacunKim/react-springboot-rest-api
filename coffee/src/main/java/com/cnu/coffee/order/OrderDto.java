package com.cnu.coffee.order;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OrderDto {

    private Long id;
    private List<Long> productIds;
    private int totalPrice;
    private OrderStatus orderStatus;
    private LocalDateTime orderTime;
    private LocalDateTime updatedTime;
}
