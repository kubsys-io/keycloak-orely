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
package io.kubsys.keycloak.orely.sign;

import java.net.http.HttpClient;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.truststore.JSSETruststoreConfigurator;

import io.kubsys.keycloak.orely.BaseFactory;

/**
 * Factory for creating {@link OrelySAMLProvider} instances.
 * <p>
 * This factory registers the custom LuxTrust Orely SAML Signature Provider
 * within Keycloak. It dynamically builds the administrative configuration
 * interface by mapping the predefined fields from
 * {@link PadesConfig}.
 * </p>
 */
public class PadesFactory extends BaseFactory {

	private static final Logger logger = Logger.getLogger(PadesFactory.class);

	private static HttpClient sharedHttpClient;

	@Override
	public String getId() {
		return "luxtrust-orely-signature";
	}

	@Override
	public String getName() {
		return "LuxTrust Orely Signature";
	}

	@Override
	public String getHelpText() {
		return "Identity provider supporting LuxTrust Orely signature";
	}

	public String getLabel() {
		return "Provider";
	}

	public Logger getLogger() {
		return logger;
	}

	public static HttpClient getSharedHttpClient() {
		return sharedHttpClient;
	}

	@Override
	public final void init(Config.Scope config) {
		super.init(config);
		getLogger().infof("LuxTrust Orely Signature %s extension loaded", getLabel());
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
		try (KeycloakSession session = factory.create()) {
			HttpClient.Builder builder = HttpClient.newBuilder()
					.followRedirects(HttpClient.Redirect.NORMAL);

			JSSETruststoreConfigurator configurator = new JSSETruststoreConfigurator(session);
			TrustManager[] trustManagers = configurator.getTrustManagers();
			if (trustManagers != null) {
				try {
					SSLContext sslContext = SSLContext.getInstance("TLS");
					sslContext.init(null, trustManagers, new SecureRandom());
					builder.sslContext(sslContext);
				} catch (Exception e) {
					throw new RuntimeException("Impossible d'initialiser le SSLContext pour l'IDP", e);
				}
			}
			sharedHttpClient = builder.build();
		}
	}

	/**
	 * Creates a new instance of the Orely Signature Provider.
	 *
	 * @param session The current Keycloak session context.
	 * @param model   The signature provider configuration model stored in the
	 *                database.
	 * @return A new {@link OrelySAMLProvider} instance.
	 */
	@Override
	public final PadesProvider create(KeycloakSession session, IdentityProviderModel model) {
		return newProvider(session, newConfig(model));
	}

	@Override
	public final PadesConfig createConfig() {
		return newConfig(null);
	}

	protected PadesConfig newConfig(IdentityProviderModel model) {
		return model == null ? new PadesConfig() : new PadesConfig(model);
	}

	protected PadesProvider newProvider(KeycloakSession session, PadesConfig config) {
		return new PadesProvider(session, config, destinationValidator);
	}

	@Override
	protected void appendCustomProperties(ProviderConfigurationBuilder builder) {

		// Challenge operation (Constant 'SIGN')
		builder.property()
				.name(CHALLENGE_SIGNATURE).label(CHALLENGE_SIGNATURE + ".label")
				.helpText(CHALLENGE_SIGNATURE + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.defaultValue(CHALLENGE_OPERATION_SIGN)
				.add();

		// Document upload URL
		builder.property()
				.name(DOCUMENT_BASE_URL)
				.label(DOCUMENT_BASE_URL + ".label")
				.helpText(DOCUMENT_BASE_URL + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.defaultValue("http://backend-host")
				.add();

		builder.property()
				.name(DOCUMENT_SERVER_TIMEOUT)
				.label(DOCUMENT_SERVER_TIMEOUT + ".label")
				.helpText(DOCUMENT_SERVER_TIMEOUT + ".help")
				.type(ProviderConfigProperty.STRING_TYPE)
				.defaultValue("5")
				.add();

	}

	@Override
	public final void close() {
		super.close();
	}

}