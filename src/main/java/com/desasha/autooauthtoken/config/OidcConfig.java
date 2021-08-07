package com.desasha.autooauthtoken.config;

import com.desasha.autooauthtoken.oidc.OidcDiscoveryService;
import com.desasha.autooauthtoken.oidc.OidcMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class OidcConfig {

	@Bean
	public OidcMetadata oidcMetadata(OidcDiscoveryService oidcDiscoveryService, Environment env) throws Exception {

		String wellKnownUri = env.getProperty("spring.security.oauth2.client.provider.kc.oidc-well-known-uri");
		OIDCProviderMetadata meta = oidcDiscoveryService.fetchProviderMetadata(wellKnownUri);
		OidcMetadata result = new OidcMetadata(meta);

		oidcDiscoveryService.fetchSigningKeys(meta).forEach(result::addSignatureKeys);
		return result;
	}

}
