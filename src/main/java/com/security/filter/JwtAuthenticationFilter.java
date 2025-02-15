package com.security.filter;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.service.JwtService;
import com.security.service.UserDetailsServiceImp;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	
	private final JwtService jwtService;
	private final UserDetailsServiceImp userDetailsService;
	
	
	

	public JwtAuthenticationFilter(JwtService jwtService, UserDetailsServiceImp userDetailsService) {
		this.jwtService = jwtService;
		this.userDetailsService = userDetailsService;
	}



	// it is time to create a filter and why is filter
	// in spring boot a filter is a java class that intercepts and process HTTP request and responses before they reach the controller
	// after the leave the controllers 
	// it is a power full mechanism for applying cross cutting concerns su as Authentication and Authorization and logging and content modification and many more 
	// using this we can checks users credentials and permission before getting access to the resource
	
	// i am using OncePerRequestFilter because i want this filter to be executed once in every incoming request and this need to be implemented 


	@Override
	protected void doFilterInternal( @NonNull HttpServletRequest request, 
			                         @NonNull HttpServletResponse response,
			                         @NonNull FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		String authHeader=request.getHeader("Authorization");
		
		if(authHeader == null || !authHeader.startsWith("Bearer ")) {
		   filterChain.doFilter(request, response);
		   return;
		} 
		
		// if the header contains the authorization header with a various token we need extract the token 
		// we need to skip the "Bearer " including space which is total seven characters long 
		// after getting the token i need to extract the username 
		
		
		String token =authHeader.substring(7);
		
		String userName =jwtService.extractUserName(token);
		
		if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			
			UserDetails userDetails=userDetailsService.loadUserByUsername(userName);
			
			if(jwtService.isValid(token, userDetails)) {
				UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
						userDetails, null,userDetails.getAuthorities());
				
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(authToken);
						
			}
		}
		
		filterChain.doFilter(request, response);
	}
	
	// we need to register this filter in our Spring security we can do this is using a by name SecurityFilterChain
}
