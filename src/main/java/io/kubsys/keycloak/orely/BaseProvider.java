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

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ExtensionsType;
import org.keycloak.events.EventBuilder;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import io.kubsys.keycloak.orely.utils.CallbackWrapper;
import io.kubsys.keycloak.orely.utils.ChallengeBuilder;
import io.kubsys.keycloak.orely.utils.Constants;
import io.kubsys.keycloak.orely.utils.ErrorCodes;
import io.kubsys.keycloak.orely.utils.LuxTrustOrelyEndpoint;
import io.kubsys.keycloak.orely.utils.Utils;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

/**
 * Custom SAML Identity Provider tailored for LuxTrust Orely integrations.
 * <p>
 * This provider overrides the standard SAML authentication flow to retrieve
 * pre-validated Pushed Authorization Request (PAR) contexts from the cache,
 * and injects specialized LuxTrust parameters as SAML extensions into the
 * AuthnRequest.
 * </p>
 */
public abstract class BaseProvider extends SAMLIdentityProvider implements Constants, ErrorCodes {

	// -------------------------------------------------------------- Attributes

	// Useful constants for SAML protocol
	private static final URI PROTOCOL_BINDINGS = URI.create(JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get());
	private static final URI NAMEID_FORMAT_ENTITY = URI.create(JBossSAMLURIConstants.NAMEID_FORMAT_ENTITY.get());

	// The keycloak current user session
	protected final KeycloakSession session;
	protected final DestinationValidator destinationValidator;

	// -------------------------------------------------------------- Lifecycle

	public BaseProvider(KeycloakSession session, BaseConfig config,
			DestinationValidator destinationValidator) {
		super(session, config, destinationValidator);
		this.session = session;
		this.destinationValidator = destinationValidator;
	}

	@Override
	public BaseConfig getConfig() {
		return (BaseConfig) super.getConfig();
	}

	public abstract Logger getLogger();

	// -------------------------------------------------------------- Authentication

	/**
	 * Initiates the SAML login process by building and signing the AuthnRequest.
	 * <p>
	 * If a {@code request_uri} is present in the client notes, it retrieves the
	 * associated context payload from the Keycloak cache, ensuring the requesting
	 * client matches the one that originally pushed the context.
	 * </p>
	 *
	 * @param request The Keycloak authentication request context.
	 * @return A JAX-RS response that redirects the user to the LuxTrust portal via
	 *         an HTTP POST binding.
	 */
	@Override
	public final Response performLogin(AuthenticationRequest request) {
		AuthenticationSessionModel authSession = request.getAuthenticationSession();
		String flowId = "unknown-flow";
		if (authSession != null && authSession.getParentSession() != null) {
			flowId = authSession.getParentSession().getId();
		}
		MDC.put("realm", request.getRealm().getName());
		MDC.put("flowId", flowId);
		MDC.put("phase", "broker_request");

		try {
			// Extract the PAR context payload passed by the business application
			Map<String, String> clientNotes = request.getAuthenticationSession().getClientNotes();
			String payloadKey = AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX
					+ ORELY_CONTEXT;
			String contextPayload = clientNotes.get(payloadKey);

			// Read context sent by /par
			JsonObject orelyContext = null;
			if (contextPayload != null && !contextPayload.isBlank()) {
				try {
					orelyContext = new JsonObject(contextPayload);
				} catch (Exception e) {
					throw new IdentityBrokerException("Bad syntax for Orely context. " + e.getMessage())
							.withMessageCode(BAD_CONTEXT_SYNTAX);
				}
			} else {
				getLogger().debug("No Orely Context found in client notes. Using default Orely portal configuration");
			}

			String portalUrl = getConfig().getSingleSignOnServiceUrl();
			getLogger().debugf("Orely Portal URL: %s", portalUrl);
			String assertionConsumerUrl = request.getRedirectUri();
			getLogger().debugf("Assertion Consumer Url: %s", assertionConsumerUrl);
			String entityId = getConfig().getEntityId();
			getLogger().debugf("Entity Id: %s", entityId);

			SAML2AuthnRequestBuilder samlBuilder = new SAML2AuthnRequestBuilder()
					.assertionConsumerUrl(assertionConsumerUrl).destination(portalUrl).issuer(entityId);
			AuthnRequestType authnRequest = samlBuilder.createAuthnRequest();
			addEnvelopeAttributes(authnRequest, orelyContext);
			byte[] documentBytes = null;
			if (orelyContext != null) {
				documentBytes = addOrelyExtensions(request, flowId, authnRequest, orelyContext);
			}
			return buildAndSignXml(request, authnRequest, portalUrl, orelyContext, documentBytes);
		} catch (IdentityBrokerException e) {
			getLogger().errorf("Could not build SAML request. %s - %s", e.getMessageCode(), e.getMessage());

			String clientRedirectUri = request.getAuthenticationSession().getRedirectUri();
			if (clientRedirectUri != null) {
				UriBuilder uriBuilder = UriBuilder.fromUri(clientRedirectUri)
						.queryParam(OAuth2Constants.ERROR, OAuthErrorException.SERVER_ERROR)
						.queryParam(OAuth2Constants.ERROR_DESCRIPTION, e.getMessageCode());

				String clientState = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
				if (clientState != null) {
					uriBuilder.queryParam("state", clientState);
				}
				return Response.seeOther(uriBuilder.build()).build();
			}
			return Response.status(Response.Status.BAD_REQUEST).entity("Invalid request: missing redirect URI")
					.build();
		} finally {
			MDC.remove("realm");
			MDC.remove("flowId");
			MDC.remove("phase");
		}
	}

	protected final void addEnvelopeAttributes(AuthnRequestType authnRequest, JsonObject orelyContext) {
		try {
			String providerName = getConfig().getProviderName();
			if (providerName != null && !providerName.isBlank()) {
				authnRequest.setProviderName(providerName);
				getLogger().debugf("Provider Name: %s", providerName);
			}

			if (orelyContext != null) {
				Boolean forceAuthn = orelyContext.getBoolean(CONTEXT_FORCE_AUTHN);
				if (forceAuthn != null && forceAuthn) {
					authnRequest.setForceAuthn(forceAuthn);
					getLogger().debugf("Force Authn: %s", forceAuthn);
				}
			}

			authnRequest.setProtocolBinding(PROTOCOL_BINDINGS);
			if (authnRequest.getIssuer() == null) {
				authnRequest.setIssuer(new NameIDType());
			}
			authnRequest.getIssuer().setFormat(NAMEID_FORMAT_ENTITY);
			String issuerName = getConfig().getIssuerName();
			getLogger().debugf("Issuer Name: %s", issuerName);
			authnRequest.getIssuer().setValue(issuerName);
		} catch (IdentityBrokerException e) {
			throw e;
		} catch (Exception e) {
			throw new IdentityBrokerException("Unable to add envelope attributes", e)
					.withMessageCode(ADD_ENV_ATTRIBUTES_ERROR);
		}
	}

	protected final byte[] addOrelyExtensions(AuthenticationRequest request, String flowId,
			AuthnRequestType authnRequest,
			JsonObject orelyContext) {
		AuthenticationSessionModel authSession = request.getAuthenticationSession();
		byte[] documentBytes = null;
		try {
			ExtensionsType extensions = authnRequest.getExtensions();
			if (extensions == null) {
				extensions = new ExtensionsType();
			}

			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			Document document = factory.newDocumentBuilder().newDocument();

			boolean addedExtension = false;
			if (orelyContext != null) {
				JsonObject attributes = orelyContext.getJsonObject(CONTEXT_ATTRIBUTES);
				if (attributes != null && !attributes.isEmpty()) {
					for (Map.Entry<String, Object> entry : attributes) {
						String attributeKey = entry.getKey();
						Object attributeValue = entry.getValue();
						if (attributeValue != null) {
							if (attributeKey.equals(CONTEXT_LANG)) {
								String langCode = attributeValue.toString().toLowerCase();
								if (langCode.equals("lu")) {
									langCode = "lb";
								}
								getLogger().debugf("Set Locale to %s", langCode);
								authSession.setClientNote(LocaleSelectorProvider.CLIENT_REQUEST_LOCALE, langCode);
							}
							if (attributeKey.equals(CONTEXT_SUBJECT_ID)) {
								attributeValue = processSubjectPrincipal(orelyContext, attributeValue);
							}
							// Technical configuration values can be logged securely
							getLogger().debugf("Set extension%s to %s", attributeKey, attributeValue);
							addExtension(document, extensions, attributeKey, attributeValue.toString());
							addedExtension = true;
						} else {
							getLogger().warnf("Ignore extension %s with no value", attributeKey);
						}
					}
				}

				JsonObject challenge = orelyContext.getJsonObject(CONTEXT_CHALLENGE);
				String encodedChallenge = buildChallenge(challenge);
				addExtension(document, extensions, SAML_CHALLENGE_NAME, encodedChallenge);
				addedExtension = true;

				List<RequestedAttribute> attributesList = new ArrayList<>();
				JsonArray requestedAttributes = orelyContext.getJsonArray(CONTEXT_REQUESTED);
				if (requestedAttributes != null && !requestedAttributes.isEmpty()) {
					for (int i = 0; i < requestedAttributes.size(); i++) {
						JsonObject requestedAttribute = requestedAttributes.getJsonObject(i);
						String name = requestedAttribute.getString(CONTEXT_REQUESTED_NAME);
						if (name == null) {
							throw new IdentityBrokerException("No name for required attribute at position " + i)
									.withMessageCode(REQUESTED_ATTRIBUTE_UNNAMED);
						}
						Boolean required = requestedAttribute.getBoolean(CONTEXT_REQUESTED_REQUIRED);
						if (required == null) {
							required = Boolean.FALSE;
						}
						attributesList.add(new RequestedAttribute(name, required, null));
						getLogger().debugf("Requested attribute %s (required=%s)", name, required.toString());
					}
				}

				documentBytes = addExtendedRequestedAttributes(authSession, flowId, orelyContext, attributesList);

				if (!attributesList.isEmpty()) {
					addRequiredAttributes(document, extensions, attributesList);
					addedExtension = true;
				}
			}

			if (addedExtension) {
				authnRequest.setExtensions(extensions);
			}

			return documentBytes;
		} catch (IdentityBrokerException e) {
			throw e;
		} catch (Exception e) {
			throw new IdentityBrokerException("Unable to add SAML extensions. " + e.getMessage(), e)
					.withMessageCode(ADD_EXTENSIONS_ERROR);
		}
	}

	protected byte[] addExtendedRequestedAttributes(AuthenticationSessionModel authSession, String flowId,
			JsonObject orelyContext,
			List<RequestedAttribute> attributes) {
		return null;
	}

	protected final String processSubjectPrincipal(JsonObject orelyContext, Object attributeValue) {
		orelyContext.put(X500_PRINCIPAL, attributeValue.toString());
		String subjectSerialNumber = attributeValue.toString();
		if (!subjectSerialNumber.matches("[0-9]+")) {
			return Utils.extractX500Attribute(subjectSerialNumber,
					"SERIALNUMBER");
		}
		return subjectSerialNumber;
	}

	/**
	 * Generates a Base64-encoded XML string representing the VASCO Challenge.
	 */
	protected final String buildChallenge(JsonObject challenge) {

		String challengeTitle = challenge == null ? null : challenge.getString(CONTEXT_TITLE);
		if (challengeTitle == null || challengeTitle.isBlank()) {
			challengeTitle = "LOGIN";
		}

		ChallengeBuilder builder = ChallengeBuilder.of(getConfig().getChallengeType(),
				getConfig().getChallengeVersion(), getConfig().getChallengeOperation());
		builder.withTitle(challengeTitle);
		getLogger().debugf("Set challenge title to %s", challengeTitle);

		if (challenge != null) {
			JsonArray keyValues = challenge.getJsonArray(CONTEXT_KEY_VALUES);
			if (keyValues != null && !keyValues.isEmpty()) {
				for (int i = 0; i < keyValues.size(); i++) {
					if (i >= 4) {
						// Maximum 4 pairs key/value
						break;
					}
					JsonObject keyValue = keyValues.getJsonObject(i);
					String key = keyValue.getString(CONTEXT_KEY_NAME);
					if (key == null || key.isBlank()) {
						getLogger().warnf("Challenge key %d: No key name found", (i + 1));
						continue;
					}
					String value = keyValue.getString(CONTEXT_VALUE_NAME);
					if (value == null || value.isBlank()) {
						getLogger().warnf("Challenge key %d: No value found for %s", (i + 1), key);
						continue;
					}
					String color = keyValue.getString(CONTEXT_COLOR_NAME);
					builder.withPair(key, value, color);
					if (color != null && !color.isBlank()) {
						getLogger().debugf("Challenge Key %d: %s=%s (Color %s)", (i + 1), key, value,
								color);
					} else {
						getLogger().debugf("Challenge Key %d: %s=%s", (i + 1), key, value);
					}
				}
			}
		}

		String extensionValue = builder.build();
		getLogger().debugf("Challenge=%s", extensionValue);
		return Base64.getEncoder().encodeToString(extensionValue.getBytes(StandardCharsets.UTF_8));
	}

	protected final void addRequiredAttributes(Document document, ExtensionsType extensions,
			List<RequestedAttribute> attributes) {
		if (attributes == null || attributes.isEmpty()) {
			return;
		}
		Element requestedAttributes = document.createElementNS(LUXTRUST_PROTOCOL_NAMESPACE,
				"luxtrustp:RequestedAttributes");
		requestedAttributes.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:luxtrustp",
				LUXTRUST_PROTOCOL_NAMESPACE);
		requestedAttributes.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:luxtrust",
				LUXTRUST_ASSERTION_NAMESPACE);

		for (RequestedAttribute attribute : attributes) {
			requestedAttributes.appendChild(addRequestedAttribute(document, attribute));
		}

		extensions.addExtension(requestedAttributes);
	}

	public record RequestedAttribute(String name, boolean required, String value) {
	};

	protected final Element addRequestedAttribute(Document document, RequestedAttribute attribute) {
		Element element = document.createElementNS(LUXTRUST_ASSERTION_NAMESPACE,
				LUXTRUST_REQUESTED_ATTRIBUTE_NAMESPACE);
		element.setAttributeNS(LUXTRUST_ASSERTION_NAMESPACE, SAML_ASSERTION_NAME,
				LUXTRUST_ATTRIBUTE_NAMESPACE + attribute.name());
		element.setAttributeNS(LUXTRUST_ASSERTION_NAMESPACE, SAML_ASSERTION_NAME_FORMAT,
				JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get());
		element.setAttributeNS(LUXTRUST_ASSERTION_NAMESPACE, SAML_ASSERTION_IS_REQUIRED,
				Boolean.toString(attribute.required()));
		if (attribute.value() != null) {
			Element valueElement = document.createElementNS(JBossSAMLURIConstants.ASSERTION_NSURI.get(),
					SAML_ATTRIBUTE_VALUE);
			valueElement.setTextContent(attribute.value());
			element.appendChild(valueElement);
		}
		return element;
	}

	protected final void addExtension(Document document, ExtensionsType extensions, String nsName,
			String extensionValue) {
		Element extensionElement = document.createElementNS(LUXTRUST_ASSERTION_NAMESPACE,
				LUXTRUST_NAMESPACE_PREFIX + nsName);
		extensionElement.setTextContent(extensionValue);
		extensionElement.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, LUXTRUST_QUALIFIED_NAME,
				LUXTRUST_ASSERTION_NAMESPACE);
		extensions.addExtension(extensionElement);
	}

	protected final Response buildAndSignXml(AuthenticationRequest request, AuthnRequestType authnRequest,
			String portalUrl, JsonObject orelyContext, byte[] documentBytes) {
		String relayState = request.getState().getEncoded();
		try {
			Document authnDocument = null;
			try {
				authnDocument = SAML2Request.convert(authnRequest);
			} catch (Exception e) {
				throw new IdentityBrokerException("Unable to build document from XML request", e)
						.withMessageCode(BUILD_DOCUMENT_ERROR);
			}
			JaxrsSAML2BindingBuilder bindingBuilder = new JaxrsSAML2BindingBuilder(session).relayState(relayState);
			KeyWrapper luxTrustKey = getConfig().getLuxTrustKey(session, session.getContext().getRealm());
			PrivateKey privateKey = (PrivateKey) luxTrustKey.getPrivateKey();
			PublicKey publicKey = (PublicKey) luxTrustKey.getPublicKey();
			X509Certificate certificate = luxTrustKey.getCertificate();

			bindingBuilder.signWith(null, privateKey, publicKey, certificate)
					.signatureAlgorithm(SignatureAlgorithm.RSA_SHA256)
					.signDocument();

			return postBinding(bindingBuilder, authnDocument, portalUrl, publicKey,
					authnRequest.getID(), request.getRedirectUri(), request.getState().getEncoded(),
					orelyContext, documentBytes);
		} catch (IdentityBrokerException e) {
			throw e;
		} catch (Exception e) {
			throw new IdentityBrokerException("Error during AuthnRequest build", e)
					.withMessageCode(AUTHN_BUILD_ERROR);
		}
	}

	protected Response postBinding(JaxrsSAML2BindingBuilder bindingBuilder, Document authnDocument,
			String portalUrl, PublicKey publicKey, String requestID, String redirectUri, String relayState,
			JsonObject orelyContext, byte[] documentBytes)
			throws ConfigurationException, ParsingException, ProcessingException, IOException {
		return bindingBuilder.postBinding(authnDocument).request(portalUrl);
	}

	@Override
	public final Object callback(RealmModel realm, UserAuthenticationIdentityProvider.AuthenticationCallback callback,
			EventBuilder event) {
		CallbackWrapper callbackWrapper = new CallbackWrapper(callback, session);
		return new LuxTrustOrelyEndpoint(session, this, getConfig(), callbackWrapper, destinationValidator);
	}

}