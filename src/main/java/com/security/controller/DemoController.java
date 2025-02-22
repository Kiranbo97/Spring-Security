package com.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

	@GetMapping("/demo")
	public ResponseEntity<String> demo(){
		return ResponseEntity.ok("Hello from secured url");
	}
	
	
	@GetMapping("/admin_only")
	public ResponseEntity<String> adminOnly(){
		return ResponseEntity.ok("hello from admin only");
		
		// we need to configure our authorization 
	}
}
