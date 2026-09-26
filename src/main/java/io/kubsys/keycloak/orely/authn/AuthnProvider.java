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

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.validators.DestinationValidator;

import io.kubsys.keycloak.orely.BaseProvider;

/**
 * Custom SAML Identity Provider tailored for LuxTrust Orely integrations.
 * <p>
 * This provider overrides the standard SAML authentication flow to retrieve
 * pre-validated Pushed Authorization Request (PAR) contexts from the cache,
 * and injects specialized LuxTrust parameters as SAML extensions into the
 * AuthnRequest.
 * </p>
 */
public class AuthnProvider extends BaseProvider {

	private static final Logger logger = Logger.getLogger(AuthnProvider.class);

	public AuthnProvider(KeycloakSession session, AuthnConfig config, DestinationValidator destinationValidator) {
		super(session, config, destinationValidator);
	}

	@Override
	public AuthnConfig getConfig() {
		return (AuthnConfig) super.getConfig();
	}

	public Logger getLogger() {
		return logger;
	}

}