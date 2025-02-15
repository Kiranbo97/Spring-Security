package com.security.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.security.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


 

@Service
public class JwtService {
	
	// Generate and validate the token we need a secret key we will use the secret key to sign the token 
	// we will also use the same key to validate the token 
	// the key should be at least 256 bit 
	// we need to chose our own secure secret key but in this project we are going to use online tool for key generation 
	
	
	private final String SECRET_KEY ="7e4d3ecf6bd3f7579e4bd5d94e1bca45d4f6e1723b23ee375bf719f6505c080c";

	
	public String extractUserName(String token) {
		// now let's get the user name from the cliam 
		
		
		return extractClaims(token, Claims::getSubject);
		
		// why subject because when generating the token we have added the user in the subject parameter 
		 
	}
	
	public boolean isValid(String token,UserDetails user) {
		// now the time to validate the creating a new public method
		
		String userName=extractUserName(token);
		
		return  (userName.equals(user.getUsername())) && !isTokenExpired(token);
		
		// we also need to check if the token is expired 
		// remember we have added expiration to our token so adding a check logical and is token expire  
	}
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	
	private Date extractExpiration(String token) {
		return extractClaims(token, Claims::getExpiration);
	}
	
	public <T> T extractClaims(String token,Function<Claims,T> resolver) {
		
		// for extracting a specific claim for example i want to access the subject 
		// i am creating new method so that we can extract a specific property from the token payload
		
		
		Claims claims=extractAllClaims(token);
		
		return resolver.apply(claims);
		
	}
	
	private Claims extractAllClaims(String token) { // extract a payload or clime from the token 
		return Jwts
				.parser()
				.verifyWith(getSigninKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
		
		// now we are extract the claims and
		// this method extract all the claims from the token that is "subject" "issuedat" "expiration" "signwith" "" 
		
	} 
	
	public String generateToken(User user) {
		String token=Jwts
				       .builder()
				         .subject(user.getUsername()) // user name is a subject for our token 
				         .issuedAt(new Date(System.currentTimeMillis()))
				         .expiration(new Date(System.currentTimeMillis()+ 24*60*60*1000))
				         .signWith(getSigninKey())
				         .compact();
		return token;
	}
	
	
	private SecretKey getSigninKey() {
		        byte[] keyBytes= Decoders.BASE64URL.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
		
	}
           
}
