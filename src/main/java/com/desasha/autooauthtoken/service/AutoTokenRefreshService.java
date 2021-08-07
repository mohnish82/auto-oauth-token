package com.desasha.autooauthtoken.service;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Objects;

import com.desasha.autooauthtoken.oidc.OidcMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

@Service
public class AutoTokenRefreshService {
	Logger log = LoggerFactory.getLogger(this.getClass());

	private OAuth2AccessToken token;

	@Autowired
	private AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientServiceAndManager;

	@Autowired
	OidcMetadata oidcMetadata;

	@Scheduled( fixedDelay = ((5 * 60 * 1000) - (5 * 1000)) ) // 60 secs - 5 secs
	public void refreshSomeData() throws ParseException {

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("kc").principal("temp1").build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientServiceAndManager.authorize(authorizeRequest);
		OAuth2AccessToken newToken = Objects.requireNonNull(authorizedClient).getAccessToken();

		if(verificationPass(newToken)) {
			token = newToken;
			log.info("Token refreshed - {}", token.getTokenValue());
		}
	}

	private boolean verificationPass(OAuth2AccessToken newToken) throws ParseException {

		SignedJWT jwt = SignedJWT.parse(newToken.getTokenValue());
		JWSVerifier verifier = new RSASSAVerifier(getPublicKey(jwt.getHeader().getKeyID()));

		try{
			jwt.verify(verifier);
		} catch (JOSEException e) {
			log.error("Token varification failed for {}", newToken.getTokenValue());
			return false;
		}

		return true;
	}

	private RSAPublicKey getPublicKey(String keyId) {
		return oidcMetadata.getSignatureKey(keyId);
	}

	public OAuth2AccessToken getToken() {
		return token;
	}

}