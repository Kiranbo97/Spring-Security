package com.security.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.security.model.User;
import com.security.repository.UserRepository;




@Service
public class UserDetailsServiceImp implements UserDetailsService{

	private final UserRepository repository;
	
	public UserDetailsServiceImp(UserRepository repository) {
		this.repository=repository;
	}
	
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		// Optional<User> user=repository.findByUserName(username);
		 
		return repository.findByUserName(username).orElseThrow(()-> new UsernameNotFoundException("User  Not Found"));
		 
//		 if(user.isEmpty()) {
//			 throw new UsernameNotFoundException("User Name is Not Found");
//		 }
//		
//		 
//		return user.get();
	}

}
