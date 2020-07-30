package com.example.demo.controllers;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.ModifyCartRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CartControllerTest {

    @InjectMocks
    CartController cartController;

    @Mock
    UserRepository userRepository;

    @Mock
    CartRepository cartRepository;

    @Mock
    ItemRepository itemRepository;

    private ModifyCartRequest request;
    private User user;
    private Item item;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        user = new User();
        user.setUsername("test");

        Cart cart = new Cart();
        cart.setUser(user);

        item = new Item();
        item.setId(1L);
        item.setDescription("First Item");
        item.setName("Item");
        item.setPrice(BigDecimal.valueOf(4.99));

        cart.addItem(item);
        user.setCart(cart);

        request = new ModifyCartRequest();
        request.setUsername("test");
        request.setItemId(1L);
        request.setQuantity(1);

        when(userRepository.findByUsername("test")).thenReturn(user);
        when(itemRepository.findById(1L)).thenReturn(Optional.of(item));
    }

    @Test
    public void addToCart() {
        final ResponseEntity<Cart> response = cartController.addTocart(request);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        Cart testCart = response.getBody();
        assertNotNull(testCart);
        assertTrue(testCart.getItems().contains(item));
        assertEquals(2, testCart.getItems().size());
        assertSame(user, testCart.getUser());
        assertEquals(BigDecimal.valueOf(9.98), testCart.getTotal());
    }

    @Test
    public void addToCartUserNameNotFound() {
        request.setUsername("wrongname");

        final ResponseEntity<Cart> response = cartController.addTocart(request);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void addToCartItemIdNotFound() {
        request.setItemId(2L);

        final ResponseEntity<Cart> response = cartController.addTocart(request);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void removeFromCart() {
        final ResponseEntity<Cart> response = cartController.removeFromcart(request);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        Cart testCart = response.getBody();
        assertNotNull(testCart);
        assertFalse(testCart.getItems().contains(item));
        assertEquals(0, testCart.getItems().size());
        assertSame(user, testCart.getUser());
    }

    @Test
    public void removeFromCartUserNameNotFound() {
        request.setUsername("wrongname");

        final ResponseEntity<Cart> response = cartController.removeFromcart(request);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void removeFromCartItemIdNotFound() {
        request.setItemId(2L);

        final ResponseEntity<Cart> response = cartController.removeFromcart(request);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }
}
