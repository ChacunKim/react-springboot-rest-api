package com.cnu.coffee.order;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/order")
public class OrderController {

    @Autowired
    private OrderService orderService;

    @PostMapping("")
    public OrderDto addOrder(@RequestBody List<Long> productIds){
        return orderService.create(productIds);
    }

    @GetMapping("/{id}")
    public OrderDto findOrder(@PathVariable("id") Long id){
        return orderService.findById(id);
    }

    @GetMapping("/all")
    public List<OrderDto> findAllOrder(){
        return orderService.findAll();
    }

    @GetMapping("/page")
    public Page<OrderDto> findOrderPage(Pageable pageable){
        return orderService.findOrderPage(pageable);
    }

    @PutMapping("")
    public OrderDto modifyOrder(@RequestBody OrderUpdateDto orderUpdateDto){
        return orderService.update(orderUpdateDto);
    }

    @PutMapping("/status")
    public OrderDto modifyStatus(@RequestBody OrderIdStautsDto orderIdStautsDto){
        return orderService.updateStatus(orderIdStautsDto);
    }

    @DeleteMapping("/{id}")
    public void removeOrder(@PathVariable("id") Long id){
        orderService.deleteById(id);
    }
}
