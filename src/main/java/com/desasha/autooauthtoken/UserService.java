package com.desasha.autooauthtoken;

import java.time.Duration;

import com.desasha.autooauthtoken.service.AutoTokenRefreshService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Service using the bearer token to make API calls.
 */
@Service
public class UserService {

	@Autowired WebClient webclient;
	@Autowired AutoTokenRefreshService tokenService;

	public String getDetails() {
		String result = webclient.post()
							.uri("... api-url ...")
							.header(HttpHeaders.AUTHORIZATION, tokenService.getToken().getTokenValue())
							.retrieve()
							.bodyToMono(String.class)
							.block(Duration.ofSeconds(3));

		return result;
	}

}