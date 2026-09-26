/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.kubsys.keycloak.orely;

import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import io.kubsys.keycloak.orely.utils.Constants;
import io.kubsys.keycloak.orely.utils.Utils;

public abstract class BaseConfig extends SAMLIdentityProviderConfig implements Constants {

	protected static final int ALLOWED_CLOCK_SKEW_SECONDS = 120;

	public BaseConfig() {
		super();
	}

	public BaseConfig(IdentityProviderModel model) {
		super(model);
		this.setAllowedClockSkew(ALLOWED_CLOCK_SKEW_SECONDS);
	}

	@Override
	public final boolean isValidateSignature() {
		return true;
	}

	@Override
	public final boolean isPostBindingAuthnRequest() {
		return true;
	}

	@Override
	public final boolean isPostBindingResponse() {
		return true;
	}

	@Override
	public final boolean isPostBindingLogout() {
		return true;
	}

	public abstract String getPortalUrl();

	public final String getIssuerName() {
		return getConfig().get(ISSUER_NAME);
	}

	public final String getProviderName() {
		return getConfig().get(PROVIDER_NAME);
	}

	public final String getChallengeType() {
		return getConfig().get(CHALLENGE_TYPE);
	}

	public final String getChallengeVersion() {
		return getConfig().get(CHALLENGE_VERSION);
	}

	public abstract String getChallengeOperation();

	/**
	 * Resolves the cryptographic key associated with the configured provider name.
	 * <p>
	 * This method searches the realm's configured Key Providers to find a match
	 * for the custom {@code providerName} field, returning the corresponding key.
	 * </p>
	 *
	 * @param session The current Keycloak session.
	 * @param realm   The current realm.
	 * @return The resolved {@link KeyWrapper}.
	 * @throws IllegalArgumentException If the provider or its keys cannot be found.
	 */
	public final KeyWrapper getLuxTrustKey(KeycloakSession session, RealmModel realm) {
		String providerName = getConfig().get(PROVIDER_NAME);

		String targetComponentId = null;
		Iterator<ComponentModel> componentIterator = realm
				.getComponentsStream(realm.getId(), KeyProvider.class.getName()).iterator();
		while (componentIterator.hasNext()) {
			ComponentModel component = componentIterator.next();
			if (providerName.equals(component.getName())) {
				targetComponentId = component.getId();
				break;
			}
		}
		if (targetComponentId == null) {
			throw new IllegalArgumentException("No key provider with name " + providerName + " found in realm keys");
		}

		Iterator<KeyWrapper> iterator = session.keys().getKeysStream(realm).iterator();
		while (iterator.hasNext()) {
			KeyWrapper key = iterator.next();
			if (targetComponentId.equals(key.getProviderId())) {
				return key;
			}
		}

		throw new IllegalArgumentException(
				"Key provider '" + providerName + "' found, but no matching keys are available");
	}

	@Override
	public void validate(RealmModel realm) {
		setSingleSignOnServiceUrl(getPortalUrl());

		String issuerName = getIssuerName();
		if (issuerName == null || issuerName.isBlank()) {
			throw new IllegalArgumentException("The issuer name is mandatory");
		}
		setEntityId(issuerName);

		String providerName = getProviderName();
		if (providerName == null || providerName.isBlank()) {
			throw new IllegalArgumentException("The provider name is mandatory to access encryption key");
		}

		normalizeOrelySigningCertificate(realm);

		String challengeType = getChallengeType();
		if (challengeType == null || challengeType.isBlank()) {
			throw new IllegalArgumentException("The challenge type is mandatory");
		}

		String challengeVersion = getChallengeVersion();
		if (challengeVersion == null || challengeVersion.isBlank()) {
			throw new IllegalArgumentException("The challenge version is mandatory");
		}

		String challengeOperation = getChallengeOperation();
		if (challengeOperation == null || challengeOperation.isBlank()) {
			throw new IllegalArgumentException("The challenge operation is mandatory");
		}

		super.validate(realm);
	}

	/**
	 * Strips PEM boundaries and whitespace from the raw certificate
	 * and stores it in the standard Keycloak SAML signing certificate property.
	 */
	protected final void normalizeOrelySigningCertificate(RealmModel realm) {
		String rawCert = getConfig().get(VALIDATION_CERTIFICATE);
		if (rawCert == null || rawCert.isBlank()) {
			throw new IllegalArgumentException("The LuxTrust Orely certificate is mandatory");
		}

		String cleanCert = Utils.normalizeCertificate(rawCert);

		try {
			X509Certificate x509Certificate = Utils.getCertificate(cleanCert);
			getConfig().put(SIGNING_CERTIFICATE_KEY, cleanCert);
			getConfig().put(VALIDATION_CERTIFICATE_SUBJECT, Utils.sanitize(x509Certificate.getSubjectX500Principal()));
			getConfig().put(VALIDATION_CERTIFICATE_ISSUER, Utils.sanitize(x509Certificate.getIssuerX500Principal()));

			DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy")
					.withZone(ZoneId.systemDefault());
			String validityDates = formatter.format(x509Certificate.getNotBefore().toInstant())
					+ " - "
					+ formatter.format(x509Certificate.getNotAfter().toInstant());
			getConfig().put(VALIDATION_CERTIFICATE_DATES, validityDates);
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"The provided LuxTrust Orely certificate is not a valid X.509 certificate.", e);
		}
	}

}