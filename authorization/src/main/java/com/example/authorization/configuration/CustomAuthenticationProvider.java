package com.example.authorization.configuration;


import com.example.authorization.service.CustomUserDetailsService;
import jakarta.annotation.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

	@Resource
	private CustomUserDetailsService customUserDetailsService;

	/**
	 * <p> The authenticate method to authenticate the request. We will get the username from the Authentication object and will
	 * use the custom @userDetailsService service to load the given user.</p>
	 * @param authentication
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
		if (!StringUtils.hasLength(username)) {
			throw new BadCredentialsException("invalid login details");
		}
		// get user details using Spring security user details service
		UserDetails user = null;
		try {
			user = customUserDetailsService.loadUserByUsername(username);

			if (user == null)
				throw new UsernameNotFoundException("user not found");
		} catch (UsernameNotFoundException exception) {
			throw new BadCredentialsException("invalid login details");
		}
		return createSuccessfulAuthentication(authentication, user);
	}

	private Authentication createSuccessfulAuthentication(final Authentication authentication, final UserDetails user) {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), authentication.getCredentials(), user.getAuthorities());
		token.setDetails(authentication.getDetails());
		return token;
	}

	@Override
	public boolean supports(Class<? extends Object> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

}

