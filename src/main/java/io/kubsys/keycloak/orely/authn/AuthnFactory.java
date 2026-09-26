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
import org.keycloak.Config;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import io.kubsys.keycloak.orely.BaseFactory;

/**
 * Factory for creating {@link AuthenticationProvider} instances.
 * <p>
 * This factory registers the custom LuxTrust Orely SAML Identity Provider
 * within Keycloak. It dynamically builds the administrative configuration
 * interface by mapping the predefined fields from
 * {@link AuthnConfig}.
 * </p>
 */
public class AuthnFactory extends BaseFactory {

	private static final Logger logger = Logger.getLogger(AuthnFactory.class);

	@Override
	public String getId() {
		return "luxtrust-orely-authn";
	}

	@Override
	public String getName() {
		return "LuxTrust Orely Authentication";
	}

	@Override
	public String getHelpText() {
		return "Identity provider supporting LuxTrust Orely authentication";
	}

	public String getLabel() {
		return "Provider";
	}

	public Logger getLogger() {
		return logger;
	}

	@Override
	public final void init(Config.Scope config) {
		super.init(config);
		getLogger().infof("LuxTrust Orely SAML Identity %s extension loaded", getLabel());
	}

	/**
	 * Creates a new instance of the Orely Identity Provider.
	 *
	 * @param session The current Keycloak session context.
	 * @param model   The identity provider configuration model stored in the
	 *                database.
	 * @return A new {@link AuthenticationProvider} instance.
	 */
	@Override
	public final AuthnProvider create(KeycloakSession session, IdentityProviderModel model) {
		return newProvider(session, newConfig(model));
	}

	@Override
	public final AuthnConfig createConfig() {
		return newConfig(null);
	}

	protected AuthnConfig newConfig(IdentityProviderModel model) {
		return model == null ? new AuthnConfig() : new AuthnConfig(model);
	}

	protected AuthnProvider newProvider(KeycloakSession session, AuthnConfig config) {
		return new AuthnProvider(session, config, destinationValidator);
	}

	@Override
	protected void appendCustomProperties(ProviderConfigurationBuilder builder) {
		// Challenge operation (Constant 'AUTH')
		builder.property()
				.name(CHALLENGE_AUTHENTICATION).label(CHALLENGE_AUTHENTICATION + ".label")
				.helpText(CHALLENGE_AUTHENTICATION + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.defaultValue(CHALLENGE_OPERATION_AUTH)
				.add();
	}

}