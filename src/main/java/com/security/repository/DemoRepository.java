package com.security.repository;

import com.security.model.User;

public class DemoRepository {
	
	// in this small application which is only focusing on creating and validating JWT this does not cause any issue however this is not best practice 
	// even it cause security leaks of our application if not handle properly
       public void demo() {
    	   User user=new User();
    	   user.setFirstName("");
    	   
       }
}
