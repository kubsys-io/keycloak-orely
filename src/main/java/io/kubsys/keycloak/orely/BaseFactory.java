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

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.saml.validators.DestinationValidator;

import io.kubsys.keycloak.orely.utils.Constants;
import io.kubsys.keycloak.orely.utils.ErrorCodes;

/**
 * Base Factory for creating Orely SAML provider instances.
 * <p>
 * This factory registers the custom LuxTrust Orely SAML Identity Provider
 * within Keycloak.
 * </p>
 */
public abstract class BaseFactory extends SAMLIdentityProviderFactory implements Constants, ErrorCodes {

	protected DestinationValidator destinationValidator;

	protected boolean isEnvironmentConfigurable() {
		return true;
	}

	@Override
	public void init(Scope config) {
		super.init(config);
		this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
	}

	/**
	 * Defines the configuration properties that will be rendered in the Keycloak
	 * Admin Console.
	 * <p>
	 * The labels and help texts are constructed dynamically using localization keys
	 * (e.g., {@code {fieldname}.label} and {@code {fieldname}.help}).
	 * </p>
	 *
	 * @return A list of configuration properties for the admin UI.
	 */
	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

		if (isEnvironmentConfigurable()) {
			// Production mode flag
			builder.property()
					.name(ORELY_PRODUCTION).label(ORELY_PRODUCTION + ".label").helpText(ORELY_PRODUCTION + ".help")
					.type(ProviderConfigProperty.BOOLEAN_TYPE).required(true).secret(false)
					.add();
		}

		// Issuer Name (e.g. https://demobank.com)
		builder.property()
				.name(ISSUER_NAME).label(ISSUER_NAME + ".label").helpText(ISSUER_NAME + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.add();

		// Provider name (e.g. SP9999)
		builder.property()
				.name(PROVIDER_NAME).label(PROVIDER_NAME + ".label").helpText(PROVIDER_NAME + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.add();

		// Response validation certificate as PEM format
		builder.property()
				.name(VALIDATION_CERTIFICATE).label(VALIDATION_CERTIFICATE + ".label")
				.helpText(getResponseValidationCertificateHelp())
				.type(ProviderConfigProperty.TEXT_TYPE).required(true).secret(false)
				.add();

		// Validation certificate subject
		builder.property()
				.name(VALIDATION_CERTIFICATE_SUBJECT).label(VALIDATION_CERTIFICATE_SUBJECT + ".label")
				.helpText(VALIDATION_CERTIFICATE_SUBJECT + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(false).secret(false)
				.add();

		// Validation certificate issuer
		builder.property()
				.name(VALIDATION_CERTIFICATE_ISSUER).label(VALIDATION_CERTIFICATE_ISSUER + ".label")
				.helpText(VALIDATION_CERTIFICATE_ISSUER + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(false).secret(false)
				.add();

		// Validation certificate validity dates
		builder.property()
				.name(VALIDATION_CERTIFICATE_DATES).label(VALIDATION_CERTIFICATE_DATES + ".label")
				.helpText(VALIDATION_CERTIFICATE_DATES + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(false).secret(false)
				.add();

		// Challenge type (Constant 'VASCO')
		builder.property()
				.name(CHALLENGE_TYPE).label(CHALLENGE_TYPE + ".label").helpText(CHALLENGE_TYPE + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.defaultValue(CHALLENGE_TYPE_VALUE)
				.add();

		// Challenge version (Constant '1.0')
		builder.property()
				.name(CHALLENGE_VERSION).label(CHALLENGE_VERSION + ".label").helpText(CHALLENGE_VERSION + ".help")
				.type(ProviderConfigProperty.STRING_TYPE).required(true).secret(false)
				.defaultValue(CHALLENGE_VERSION_VALUE)
				.add();

		appendCustomProperties(builder);

		return builder.build();
	}

	protected String getResponseValidationCertificateHelp() {
		return VALIDATION_CERTIFICATE + ".help";
	}

	protected void appendCustomProperties(ProviderConfigurationBuilder builder) {

	}
}