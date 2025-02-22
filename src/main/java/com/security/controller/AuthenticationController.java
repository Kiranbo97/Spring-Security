package com.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.model.AuthenticationResponse;
import com.security.model.User;
import com.security.service.AuthenticationService;

@RestController
@RequestMapping
public class AuthenticationController {

	
	private final AuthenticationService authService;

	public AuthenticationController(AuthenticationService authService) {

		this.authService = authService;
	}

	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(@RequestBody User request) {

		System.out.println("Register API hit with user: " + request.getUserName());
	    System.out.println("Request Body: " + request); // Log the entire request object/
		
		return ResponseEntity.ok(authService.register(request));
	}

	@PostMapping("/login")
	public ResponseEntity<AuthenticationResponse> login(@RequestBody User request) {
                     return ResponseEntity.ok(authService.authenticate(request));
	}

}
