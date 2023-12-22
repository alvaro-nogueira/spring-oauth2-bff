package com.example.resourcesever.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Collection;

@RestController
public class CustomerController {


	@GetMapping("/customers")
	@PreAuthorize("hasAuthority('SCOPE_user.read')")
	public Collection<Customer> customers() {

		Customer c1 = new Customer();
		c1.setEmail("teste@mail.com");
		c1.setName("teste");
		c1.setId(1);
		Customer c2 = new Customer();
		c2.setEmail("teste2@mail.com");
		c2.setName("teste2");
		c2.setId(2);

		Customer c3 = new Customer();
		c3.setEmail("teste3@mail.com");
		c3.setName("teste3");
		c3.setId(3);

//		Jwt j = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//		System.out.println(j.getIssuer());
//		System.out.println(j.getTokenValue());
//		System.out.println(SecurityContextHolder.getContext().getAuthentication().getCredentials().toString());

		return Arrays.asList(c1, c2, c3);
	}

}
