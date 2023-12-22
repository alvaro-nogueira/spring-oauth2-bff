package com.example.authorization.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Configuration
@SuppressWarnings("deprecation")
public class SecurityConfig {

	@Autowired
	private CustomAuthenticationProvider customAuthenticationProvider;

	@Bean
	@Order(1)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.oauth2ResourceServer(oauth2 -> oauth2
						.jwt(Customizer.withDefaults()));
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults());
		http.exceptionHandling(e -> e
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));

		return http.build();


	}


	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

		http
				.authorizeHttpRequests(authorize ->
						authorize.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
		.authenticationProvider(customAuthenticationProvider);
		;
		return http.build();
	}

//	@Bean
//	public UserDetailsService userDetailsService() {
//		var user1 = User.withUsername("user")
//				.password("pass")
//				.authorities("read")
//				.build();
//		return new InMemoryUserDetailsManager(user1);
//	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("srm")
				.clientSecret("srm")
				.scopes(scopes -> scopes.addAll(Set.of("read","user.read", "user.write", OidcScopes.OPENID)))
				.redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
				//.redirectUri("https://oauthdebugger.com/debug")
				//.redirectUri("https://springone.io/authorized")

				// by default only this
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				// added
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public TokenSettings tokenSettings() {
		return TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofSeconds(20))
				.build();
	}

//	@Bean
//	public ClientSettings clientSettings() {
//		return ClientSettings.builder()
//				.requireAuthorizationConsent(false)
//				.requireProofKey(false)
//				.build();
//	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	public static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}