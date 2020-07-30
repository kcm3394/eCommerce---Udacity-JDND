package com.example.demo.controllers;

import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.repositories.ItemRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ItemControllerTest {

    @InjectMocks
    ItemController itemController;

    @Mock
    ItemRepository itemRepository;

    private List<Item> items;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

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

        items = new ArrayList<>();
        items.add(item1);
        items.add(item2);

        when(itemRepository.findAll()).thenReturn(items);
        when(itemRepository.findById(1L)).thenReturn(Optional.of(item1));
        when(itemRepository.findByName("Item")).thenReturn(items);
    }

    @Test
    public void getItems() {
        final ResponseEntity<List<Item>> response = itemController.getItems();
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        List<Item> testList = response.getBody();
        assertNotNull(testList);
        assertArrayEquals(items.toArray(), testList.toArray());
    }

    @Test
    public void getItemById() {
        final ResponseEntity<Item> response = itemController.getItemById(1L);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        Item testItem = response.getBody();
        assertNotNull(testItem);
        assertEquals("First Item", testItem.getDescription());
        assertEquals("Item1", testItem.getName());
        assertEquals(BigDecimal.valueOf(4.99), testItem.getPrice());
    }

    @Test
    public void getItemByIdNotFound() {
        final ResponseEntity<Item> response = itemController.getItemById(3L);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void getItemsByName() {
        final ResponseEntity<List<Item>> response = itemController.getItemsByName("Item");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        List<Item> testList = response.getBody();
        assertNotNull(testList);
        assertArrayEquals(items.toArray(), testList.toArray());
    }

    @Test
    public void getItemsByNameNotFound() {
        final ResponseEntity<List<Item>> response = itemController.getItemsByName("Box");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }
}
