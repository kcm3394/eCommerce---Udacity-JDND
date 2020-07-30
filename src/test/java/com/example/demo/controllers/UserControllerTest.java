package com.example.demo.controllers;

import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

public class UserControllerTest {

    @InjectMocks
    UserController userController;

    @Mock
    UserRepository userRepository;

    @Mock
    CartRepository cartRepository;

    @Mock
    BCryptPasswordEncoder encoder;

    private CreateUserRequest request;
    private User user;

    //https://nearsoft.com/blog/annotation-magic-with-mockito-injectmocks/
    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        request = new CreateUserRequest();
        request.setUsername("test");
        request.setPassword("testPassword");
        request.setConfirmPassword("testPassword");

        when(encoder.encode("testPassword")).thenReturn("thisIsHashed");

        user = new User();
        user.setId(0L);
        user.setUsername("test");
        user.setPassword("testPassword");

        when(userRepository.findByUsername("test")).thenReturn(user);
        when(userRepository.findById(0L)).thenReturn(Optional.of(user));
    }

    @Test
    public void createUser() {
        final ResponseEntity<User> response = userController.createUser(request);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        User testUser = response.getBody();
        assertNotNull(testUser);
        assertEquals(0, testUser.getId());
        assertEquals("test", testUser.getUsername());
        assertEquals("thisIsHashed", testUser.getPassword());
    }

    @Test
    public void createUserPasswordRequirementNotMet() {
        request.setPassword("test");
        request.setConfirmPassword("test");

        final ResponseEntity<User> response = userController.createUser(request);
        assertNotNull(response);
        assertEquals(400, response.getStatusCodeValue());
    }

    @Test
    public void createUserPasswordsDoNotMatch() {
        request.setConfirmPassword("testpassword");

        final ResponseEntity<User> response = userController.createUser(request);
        assertNotNull(response);
        assertEquals(400, response.getStatusCodeValue());
    }

    @Test
    public void findByUsername() {
        final ResponseEntity<User> response = userController.findByUserName("test");
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        User testUser = response.getBody();
        assertNotNull(testUser);
        assertEquals(0, testUser.getId());
        assertEquals("test", testUser.getUsername());
        assertEquals("testPassword", testUser.getPassword());
    }

    @Test
    public void findByUserNameNotFound() {
        final ResponseEntity<User> response = userController.findByUserName("wrong");
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }

    @Test
    public void findById() {
        final ResponseEntity<User> response = userController.findById(0L);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());

        User testUser = response.getBody();
        assertNotNull(testUser);
        assertEquals(0, testUser.getId());
        assertEquals("test", testUser.getUsername());
        assertEquals("testPassword", testUser.getPassword());
    }

    @Test
    public void findByIdNotFound() {
        final ResponseEntity<User> response = userController.findById(1L);
        assertNotNull(response);
        assertEquals(404, response.getStatusCodeValue());
    }
}
