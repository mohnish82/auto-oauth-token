package com.desasha.autooauthtoken.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

@Service
public class OidcDiscoveryService {

	Logger log = LoggerFactory.getLogger(OidcDiscoveryService.class);

	/**
	 * Fetches configuration from the discovery url and constructs a provider metadata instance to represent it.
	 *
	 * @param discoveryUrl Open Id Connect configuration well known endpoint url
	 * @return OIDCProviderMetadata Provider metadata
	 */
	public OIDCProviderMetadata fetchProviderMetadata(String discoveryUrl) throws Exception {
		if(discoveryUrl == null || discoveryUrl.trim().length() < 1)
			return null;

		OIDCProviderMetadata metadata = null;

		try (InputStream stream = new URL(discoveryUrl).openStream();) {
			String providerInfo = null;
			try (java.util.Scanner s = new java.util.Scanner(stream)) {
			  providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
			}

			metadata = OIDCProviderMetadata.parse(providerInfo);
		}

		return metadata;
	}

	/**
	 * Fetches provider public keys for signature verification. Returns a map of keyId-key.
	 * @throws com.nimbusds.oauth2.sdk.ParseException
	 */
	public Map<String,RSAPublicKey> fetchSigningKeys(OIDCProviderMetadata metadata) {
		Map<String,RSAPublicKey> pubKeys = new HashMap<>();

		try {
			StringBuilder builder = new StringBuilder();
			try (Scanner scanner = new Scanner(metadata.getJWKSetURI().toURL().openStream());) {
				while (scanner.hasNext()) {
					builder.append(scanner.next());
				}
			}

			JSONObject json = JSONObjectUtils.parse(builder.toString());

			// Find the RSA signing keys
			for (Object obj : (JSONArray) json.get("keys")) {
				JSONObject key = (JSONObject) obj;

				if (key.get("use").equals("sig") && key.get("kty").equals("RSA")) {
					try {
						pubKeys.put(key.getAsString("kid"), RSAKey.parse(key).toRSAPublicKey());
					}
					catch(java.text.ParseException | JOSEException e) {
						// Keep going and don't error out if one of the keys is invalid.
					}
				}
			}
		}
		catch(ParseException | IOException e) {
			log.error("Error occured while fetching provider signing keys", e);
		}

		return pubKeys;
	}


}
