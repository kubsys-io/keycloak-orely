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
package io.kubsys.keycloak.orely.authn;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

import io.kubsys.keycloak.orely.BaseConfig;

public class AuthnConfig extends BaseConfig {

	public AuthnConfig() {
		super();
	}

	public AuthnConfig(IdentityProviderModel model) {
		super(model);
	}

	@Override
	public String getPortalUrl() {
		boolean isProd = Boolean.parseBoolean(getConfig().get(ORELY_PRODUCTION));
		String baseUrl = isProd ? ORELY_PORTAL_URL_PRODUCTION : ORELY_PORTAL_URL_TEST;
		baseUrl += "auth";
		return baseUrl;
	}

	@Override
	public final String getChallengeOperation() {
		return getConfig().get(CHALLENGE_AUTHENTICATION);
	}

	@Override
	public void validate(RealmModel realm) {
		// The target LuxTrust Orely portal URL
		setSingleSignOnServiceUrl(getPortalUrl());

		super.validate(realm);

		// The issuer name (e.g. https://demobank.com)
		String issuerName = getIssuerName();
		if (issuerName == null || issuerName.isBlank()) {
			throw new IllegalArgumentException("The issuer name is mandatory");
		}
		setEntityId(issuerName);

		// The provider name (e.g. SP0455). Used as encryption key identifier
		String providerName = getProviderName();
		if (providerName == null || providerName.isBlank()) {
			throw new IllegalArgumentException("The provider name is mandatory to access encryption key");
		}

		// The certificate used by LuxTrust to sign response and used by the plugin to
		// validate signatures
		normalizeOrelySigningCertificate(realm);

		// Constant value provided by LuxTrust (e.g. VASCO)
		String challengeType = getChallengeType();
		if (challengeType == null || challengeType.isBlank()) {
			throw new IllegalArgumentException("The challenge type is mandatory");
		}

		// Constant value provided by LuxTrust (e.g. 1.0)
		String challengeVersion = getChallengeVersion();
		if (challengeVersion == null || challengeVersion.isBlank()) {
			throw new IllegalArgumentException("The challenge version is mandatory");
		}

		// Constant value provided by LuxTrust (e.g. AUTH)
		String challengeOperation = getChallengeOperation();
		if (challengeOperation == null || challengeOperation.isBlank()) {
			throw new IllegalArgumentException("The challenge operation is mandatory");
		}

	}

}