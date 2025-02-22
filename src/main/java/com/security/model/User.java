package com.security.model;

import java.util.Collection;
import java.util.List;



import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "user")
public class User implements UserDetails{ 
	
	// implementing Authentication and Authorization first we need user
	// for user authentication and authorization spring security uses special object that is UserDetails 
	// this is interface and need to implement 
	
	// when a class or method or variable does not have an access modifier associated with it java assigns a default access
	
	// for authentication purpose spring security uses another special object "named user detail service" to make our development 
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "id")
	private Integer id;

	@Column(name = "first_name")
	private String firstName;

	@Column(name = "last_name")
	private String lastName;

	@Column(name = "username")
	private String userName;

	@Column(name = "password")
	private String password;

	// another property that our user will have a "role" like 'Admin' or 'Agent' or
	// 'Normal User'
	// various Role are available in different libraries but i have create my own
	// Role class
	
	@Enumerated(value = EnumType.STRING)
	private Role role;
	
	
	
	// single user having multiple tokens so we need List of tokens
	// this name is the same as the field name we have provided for user in our Token table 
	@OneToMany(mappedBy = "user")
	private List<Token> tokens;
	
	
	
	

	public List<Token> getTokens() {
		return tokens;
	}

	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Role getRole() {
		return role;
	}

	public void setRole(Role role) {
		this.role = role;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		// this method should return the list of role that our user have 
		// our user should have only one role 
		// we need to give the list of here 
		
		
		return List.of(new SimpleGrantedAuthority(role.name()));
	}
	
	@Override
    public boolean isEnabled() {
        return true;
    }
	
	 @Override
	 public boolean isCredentialsNonExpired() {
	        return true;
    }

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return this.userName;
	}
	
	@Override
	public boolean isAccountNonLocked() {
	        return true;
	}

	 
	@Override
	public boolean isAccountNonExpired() {
	        return true;
    }
	
	
}
