package com.example.demo.controllers;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.UserOrder;
import com.example.demo.model.persistence.repositories.OrderRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class OrderControllerTest {

    @InjectMocks
    OrderController orderController;

    @Mock
    UserRepository userRepository;

    @Mock
    OrderRepository orderRepository;

    private User user;
    private Cart cart;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        user = new User();
        user.setUsername("test");

        cart = new Cart();
        cart.setUser(user);

        Item item1 = new Item();
        item1.setId(1L);
        item1.setDescription("First Item");
        item1.setName("Item1");
        item1.setPrice(BigDecimal.valueOf(4.99));
        cart.addItem(item1);

        Item item2 = new Item();
        item2.setId(2L);
        item2.setDescription("Second Item");
        item2.setName("Item2");
        item2.setPrice(BigDecimal.valueOf(8.99));
        cart.addItem(item2);

        user.setCart(cart);

        when(userRepository.findByUsername("test")).thenReturn(user);
    }

    @Test
    public void submitSuccess() {
        final ResponseEntity<UserOrder> response = orderController.submit("test");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        verify(userRepository, times(1)).findByUsername("test");
        verify(orderRepository, times(1)).save(any(UserOrder.class));

        UserOrder testUserOrder = response.getBody();
        assertNotNull(testUserOrder);
        assertEquals(2, testUserOrder.getItems().size());
        assertEquals(user, testUserOrder.getUser());
        assertEquals(BigDecimal.valueOf(13.98), testUserOrder.getTotal());
    }

    @Test
    public void submitUserNameNotFound() {
        final ResponseEntity<UserOrder> response = orderController.submit("wrong");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void getOrdersForUser() {
        List<UserOrder> userOrders = createOrderHistoryForUser(user);
        when(orderRepository.findByUser(user)).thenReturn(userOrders);

        final ResponseEntity<List<UserOrder>> response = orderController.getOrdersForUser("test");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        verify(userRepository, times(1)).findByUsername("test");
        verify(orderRepository, times(1)).findByUser(user);

        List<UserOrder> testUserOrders = response.getBody();
        assertNotNull(testUserOrders);
        assertArrayEquals(userOrders.toArray(), testUserOrders.toArray());
    }

    @Test
    public void getOrdersForUserUserNameNotFound() {
        final ResponseEntity<List<UserOrder>> response = orderController.getOrdersForUser("wrong");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    private List<UserOrder> createOrderHistoryForUser(User user) {
        UserOrder firstOrder = new UserOrder();
        firstOrder.setId(1L);
        firstOrder.setItems(createListOfItems());
        firstOrder.setUser(user);
        firstOrder.setTotal(BigDecimal.valueOf(4.99 + 8.99));

        UserOrder secondOrder = new UserOrder();
        secondOrder.setId(2L);
        secondOrder.setItems(createAnotherListOfItems());
        secondOrder.setUser(user);
        secondOrder.setTotal(BigDecimal.valueOf(16.50 + 27.50));

        List<UserOrder> userOrders = new ArrayList<>();
        userOrders.add(firstOrder);
        userOrders.add(secondOrder);

        return userOrders;
    }

    private List<Item> createListOfItems() {
        Item item1 = new Item();
        item1.setId(1L);
        item1.setDescription("First Item");
        item1.setName("Item1");
        item1.setPrice(BigDecimal.valueOf(4.99));

        Item item2 = new Item();
        item2.setId(2L);
        item2.setDescription("Second Item");
        item2.setName("Item2");
        item2.setPrice(BigDecimal.valueOf(8.99));

        List<Item> items = new ArrayList<>();
        items.add(item1);
        items.add(item2);

        return items;
    }

    private List<Item> createAnotherListOfItems() {
        Item item3 = new Item();
        item3.setId(3L);
        item3.setDescription("Third Item");
        item3.setName("Item3");
        item3.setPrice(BigDecimal.valueOf(16.50));

        Item item4 = new Item();
        item4.setId(4L);
        item4.setDescription("Fourth Item");
        item4.setName("Item4");
        item4.setPrice(BigDecimal.valueOf(27.50));

        List<Item> itemsList2 = new ArrayList<>();
        itemsList2.add(item3);
        itemsList2.add(item4);

        return itemsList2;
    }
}
