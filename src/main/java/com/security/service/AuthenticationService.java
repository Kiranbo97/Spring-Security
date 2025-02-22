package com.security.service;


import java.util.List;
import java.util.Optional;


import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.webauthn.management.ImmutableRelyingPartyRegistrationRequest;
import org.springframework.stereotype.Service;

import com.security.model.AuthenticationResponse;
import com.security.model.Token;
import com.security.model.User;
import com.security.repository.TokenRepository;
import com.security.repository.UserRepository;

@Service
public class AuthenticationService {
     
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	
	private final AuthenticationManager authenticationManager;
	
	private final TokenRepository tokenRepository;
	
	
	public AuthenticationService(UserRepository userRepository, PasswordEncoder passwordEncoder,
			JwtService jwtService,AuthenticationManager authenticationManager,
			TokenRepository tokenRepository) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authenticationManager=authenticationManager;
		this.tokenRepository=tokenRepository;
	}
	
	
	public AuthenticationResponse register(User request) {
		User user=new User();
	    user.setFirstName(request.getFirstName());
	    user.setLastName(request.getLastName());
	    user.setUserName(request.getUsername());
	    user.setPassword(passwordEncoder.encode(request.getPassword()));
	    
	    user.setRole(request.getRole());
	    
	    user=userRepository.save(user);
	    
	    String jwt=jwtService.generateToken(user);
	    
	    saveUserToken(jwt, user);
	    
	    
	    
	    return new AuthenticationResponse(jwt);
	    
	}


	private void saveUserToken(String jwt, User user) {
		
		// save the generated token 
		
		Token token=new Token();
	     token.setToken(jwt);
	     token.setLoggedOut(false);
	     token.setUser(user);
	     tokenRepository.save(token);
	}
	
	
	
	
	public AuthenticationResponse authenticate(User request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getUsername(), 
						request.getPassword()
						)
				);
		
		User user =userRepository.findByUserName(request.getUsername()).orElseThrow();
		String token=jwtService.generateToken(user);
		
		revokeAllTokenByUser(user);
		
		saveUserToken(token, user);
		
		
		
		return new AuthenticationResponse(token);
	}


	private void revokeAllTokenByUser(User user) {
		List<Token> validTokenListByUser=tokenRepository.findAllTokenByUser(user.getId());
		
		if(!validTokenListByUser.isEmpty()) {
			validTokenListByUser.forEach(t->t.setLoggedOut(true));
		}
		
		tokenRepository.saveAll(validTokenListByUser);
	}
	
}
