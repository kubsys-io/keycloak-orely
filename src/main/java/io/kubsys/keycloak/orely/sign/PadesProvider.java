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

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;

import io.kubsys.keycloak.orely.BaseProvider;
import io.kubsys.keycloak.orely.utils.PadesUtils;
import io.kubsys.keycloak.orely.utils.PadesUtils.SignaturePlacement;
import io.vertx.core.json.JsonObject;

/**
 * Custom SAML Identity Provider tailored for LuxTrust Orely integrations.
 * <p>
 * This provider overrides the standard SAML authentication flow to retrieve
 * pre-validated Pushed Authorization Request (PAR) contexts from the cache,
 * and injects specialized LuxTrust parameters as SAML extensions into the
 * AuthnRequest.
 * </p>
 */
public class PadesProvider extends BaseProvider {

	private static final Logger logger = Logger.getLogger(PadesProvider.class);

	public PadesProvider(KeycloakSession session, PadesConfig config,
			DestinationValidator destinationValidator) {
		super(session, config, destinationValidator);
	}

	@Override
	public PadesConfig getConfig() {
		return (PadesConfig) super.getConfig();
	}

	public Logger getLogger() {
		return logger;
	}

	@Override
	protected final byte[] addExtendedRequestedAttributes(AuthenticationSessionModel authSession, String flowId,
			JsonObject orelyContext, List<RequestedAttribute> attributes) {

		JsonObject signatureContext = orelyContext.getJsonObject(CONTEXT_SIGNATURE);
		if (signatureContext == null) {
			throw new IdentityBrokerException("The signature context is mandatory in Orely Context")
					.withMessageCode(MISSING_SIGNATURE_CONTEXT);
		}

		// The context must contain the path allowing to download the document to sign
		String documentDownloadUrl = signatureContext.getString(CONTEXT_DOCUMENT_DOWNLOAD_PATH);
		if (documentDownloadUrl == null || documentDownloadUrl.isBlank()) {
			throw new IdentityBrokerException(CONTEXT_DOCUMENT_DOWNLOAD_PATH + " is mandatory in Orely Context")
					.withMessageCode(MISSING_DOCUMENT_DOWNLOAD_PATH);
		}
		if (documentDownloadUrl.charAt(0) != '/') {
			throw new IdentityBrokerException(CONTEXT_DOCUMENT_DOWNLOAD_PATH + " must start with a slash")
					.withMessageCode(BAD_DOCUMENT_DOWNLOAD_PATH);
		}
		documentDownloadUrl = getConfig().getDocumentUrl(documentDownloadUrl);
		documentDownloadUrl = checkBaseUrl(getConfig().getDocumentBaseUrl(), documentDownloadUrl);
		logger.debugf("Document download URL: %s", documentDownloadUrl);

		// The context must contain the path allowing to upload the signed document
		String documentUploadUrl = signatureContext.getString(CONTEXT_DOCUMENT_UPLOAD_PATH);
		if (documentUploadUrl == null || documentUploadUrl.isBlank()) {
			throw new IdentityBrokerException(CONTEXT_DOCUMENT_UPLOAD_PATH + " is mandatory in Orely Context")
					.withMessageCode(MISSING_DOCUMENT_UPLOAD_PATH);
		}
		if (documentUploadUrl.charAt(0) != '/') {
			throw new IdentityBrokerException(CONTEXT_DOCUMENT_UPLOAD_PATH + " must start with a slash")
					.withMessageCode(BAD_DOCUMENT_UPLOAD_PATH);
		}
		documentUploadUrl = getConfig().getDocumentUrl(documentUploadUrl);
		documentUploadUrl = checkBaseUrl(getConfig().getDocumentBaseUrl(), documentUploadUrl);
		logger.debugf("Document upload URL: %s", documentUploadUrl);
		authSession.setAuthNote(CONTEXT_DOCUMENT_UPLOAD_PATH, documentUploadUrl);
		authSession.setAuthNote(DOCUMENT_SERVER_TIMEOUT, String.valueOf(getConfig().getDocumentServerTimeout()));

		try {
			String realmName = session.getContext().getRealm().getName();
			String idpAlias = getConfig().getAlias();
			String customUserAgent = String.format("%s/%s", realmName, idpAlias);
			HttpRequest httpRequest = HttpRequest.newBuilder()
					.uri(URI.create(documentDownloadUrl))
					.header(HTTP_HEADER_ACCEPT, MIME_TYPE_APPLICATION_PDF)
					.header(HTTP_HEADER_USER_AGENT, customUserAgent)
					.header(HTTP_HEADER_X_CORRELATION_ID, flowId)
					.GET()
					.timeout(Duration.ofSeconds(getConfig().getDocumentServerTimeout()))
					.build();

			HttpResponse<byte[]> response = PadesFactory.getSharedHttpClient().send(httpRequest,
					HttpResponse.BodyHandlers.ofByteArray());
			if (response.statusCode() != 200) {
				throw new IdentityBrokerException(
						"Failed to download document to sign. HTTP Status: " + response.statusCode())
						.withMessageCode(DOWNLOAD_DOCUMENT_ERROR);
			}

			byte[] pdfBytes = response.body();

			Optional<String> signaturePlacementConfig = response.headers().firstValue(HEADER_SIGNATURE_PLACEMENT);

			SignaturePlacement signaturePlacement = null;
			if (signaturePlacementConfig.isPresent()) {
				signaturePlacement = getSignaturePlacement(flowId, signaturePlacementConfig.get(), customUserAgent);
				logger.debugf("Signature placement configuration: %s", signaturePlacementConfig.get());
			} else {
				throw new IdentityBrokerException("Missing document signature placement in response headers")
						.withMessageCode(SIGNATURE_PLACEMENT_MISSING);
			}

			String signaturePolicy = getSignatureHeader(response.headers(), HEADER_SIGN_POLICY, SIGN_FULLY_DELEGATED);
			String signatureQAA = getSignatureHeader(response.headers(), HEADER_SIGN_QAA, null);
			String signatureForm = getSignatureHeader(response.headers(), HEADER_SIGN_FORM, SIGN_FORM_T);
			String commitmentType = getSignatureHeader(response.headers(), HEADER_SIGN_COMMITMENT,
					SIGN_COMMITMENT_APPROVAL);

			String xmlRequest = PadesUtils.generateSignatureRequest(signaturePolicy, signatureQAA, signatureForm,
					commitmentType, signaturePlacement, pdfBytes);

			String encodedRequest = Base64.getEncoder().encodeToString(xmlRequest.getBytes(StandardCharsets.UTF_8));
			attributes.add(new RequestedAttribute(DSS_SIGNATURE_REQUEST, true, encodedRequest));
			return pdfBytes;
		} catch (IdentityBrokerException e) {
			throw e;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IdentityBrokerException("Document download interrupted. " + e.getMessage(), e)
					.withMessageCode(DOWNLOAD_DOCUMENT_INTERRUPTED);
		} catch (Exception e) {
			throw new IdentityBrokerException(
					"Error processing document " + documentDownloadUrl + " for signature. " + e.getMessage(), e)
					.withMessageCode(DOCUMENT_SIGNATURE_ERROR);
		}
	}

	/**
	 * Resolves and normalizes a provided URL against a configured base URL,
	 * ensuring that the resulting path does not attempt to escape the allowed base
	 * directory.
	 * <p>
	 * This method mitigates Directory Traversal (Path Traversal) vulnerabilities
	 * by preventing potentially malicious inputs (e.g., paths containing
	 * {@code ../}) from generating requests outside the intended backend scope.
	 * </p>
	 *
	 * @param baseUrl the trusted base URL (e.g.,
	 *                {@code http://backend-host/api/docs/})
	 * @param fullUrl the untrusted or dynamically generated URL to resolve
	 * @return the safely resolved and normalized URL string
	 * @throws IdentityBrokerException if the resolved path falls outside the bounds
	 *                                 of the base URL
	 */
	private static String checkBaseUrl(String baseUrl, String fullUrl) {
		URI baseUri = URI.create(baseUrl);
		URI resolvedUri = baseUri.resolve(fullUrl).normalize();
		if (!resolvedUri.getPath().startsWith(baseUri.getPath())) {
			throw new IdentityBrokerException("Invalid document path detected")
					.withMessageCode(BAD_DOCUMENT_DOWNLOAD_PATH);
		}
		return resolvedUri.toString();
	}

	/**
	 * Builds a placement definition that must be added to a PDF document for
	 * signature. The placement definition is read from HTTP headers and parsed to
	 * extract the following attributes:
	 * {@code orely-sign-placement: x= y= w= h= p= watermark= fieldname=}
	 * where:
	 * <ul>
	 * <li>{@code p}: the page number where the watermark must be added</li>
	 * <li>{@code x}: the horizontal position in pixels</li>
	 * <li>{@code y}: the vertical position in pixels starting from page bottom</li>
	 * <li>{@code w}: the watermark width in pixels</li>
	 * <li>{@code h}: the watermark height in pixels</li>
	 * <li>{@code watermark}: URL to download a watermark image</li>
	 * <li>{@code fieldname}: Name of the field in PDF document</li>
	 * </ul>
	 * 
	 * @param flowId          the correlation flow ID for logging and tracing
	 * @param config          the raw configuration string from the HTTP header
	 * @param customUserAgent the custom user-agent header value for tracking
	 * @return a populated {@link SignaturePlacement} record containing coordinates,
	 *         page, field name and image bytes
	 * @throws IdentityBrokerException if a value is incorrect or the watermark
	 *                                 download fails
	 */
	private SignaturePlacement getSignaturePlacement(String flowId, String config, String customUserAgent) {

		Map<String, String> props = new HashMap<>();
		for (String part : config.split("\\s+")) {
			String[] kv = part.split("=", 2);
			if (kv.length == 2 && !kv[1].isBlank()) {
				props.put(kv[0], kv[1]);
			}
		}

		// Field name is optional
		String fieldName = props.get(FIELD_NAME);
		if (fieldName == null || fieldName.isBlank()) {
			fieldName = null;
		}

		// Watermark is optional
		String wmUrl = props.get(WATERMARK);
		byte[] watermarkBytes = null;
		if (wmUrl != null && !wmUrl.isBlank()) {
			try {
				HttpRequest httpRequest = HttpRequest.newBuilder()
						.uri(URI.create(wmUrl))
						.header(HTTP_HEADER_USER_AGENT, customUserAgent)
						.header(HTTP_HEADER_X_CORRELATION_ID, flowId)
						.GET()
						.timeout(Duration.ofSeconds(getConfig().getDocumentServerTimeout()))
						.build();

				HttpResponse<byte[]> response = PadesFactory.getSharedHttpClient().send(httpRequest,
						HttpResponse.BodyHandlers.ofByteArray());
				if (response.statusCode() != 200) {
					throw new RuntimeException("HTTP Status: " + response.statusCode());
				}
				watermarkBytes = response.body();
			} catch (Exception e) {
				throw new IdentityBrokerException("Failed to download watermark image from " + wmUrl
						+ ". " + e.getMessage(), e)
						.withMessageCode(DOWNLOAD_WATERMARK_ERROR);
			}
		}
		String xProperty = props.get(PLACEMENT_X);
		String yProperty = props.get(PLACEMENT_Y);
		String wProperty = props.get(PLACEMENT_WIDTH);
		String hProperty = props.get(PLACEMENT_HEIGHT);
		String pProperty = props.get(PLACEMENT_PAGE);

		boolean allPresent = (xProperty != null && yProperty != null && wProperty != null && hProperty != null
				&& pProperty != null);
		boolean allMissing = (xProperty == null && yProperty == null && wProperty == null && hProperty == null
				&& pProperty == null);
		if (!allPresent && !allMissing) {
			throw new IdentityBrokerException(
					"Partial signature position in header : " + config)
					.withMessageCode(PARTIAL_SIGNATURE_POSITION);
		}

		Integer x = getPositionAttribute(config, PLACEMENT_X, xProperty, 0);
		Integer y = getPositionAttribute(config, PLACEMENT_Y, yProperty, 0);
		Integer w = getPositionAttribute(config, PLACEMENT_WIDTH, wProperty, 0);
		Integer h = getPositionAttribute(config, PLACEMENT_HEIGHT, hProperty, 0);
		Integer p = getPositionAttribute(config, PLACEMENT_PAGE, pProperty, 0);
		return new SignaturePlacement(x, y, w, h, p, fieldName, watermarkBytes);
	}

	/**
	 * Extracts and validates an integer attribute from the watermark configuration
	 * properties. Ensures the attribute is present, can be parsed as a valid
	 * integer, and meets a minimum threshold.
	 * 
	 * @param config   the raw configuration string from the HTTP header for error
	 *                 reporting
	 * @param name     the name of the attribute
	 * @param value    the value of the attribute
	 * @param minValue the minimum acceptable integer value for this attribute
	 * @return the parsed and validated integer value
	 * @throws IdentityBrokerException if the attribute is missing, malformed, or
	 *                                 below the minimum value
	 */
	private static Integer getPositionAttribute(String config, String name, String value, int minValue) {
		if (value == null) {
			return null;
		}
		if (!value.matches("[0-9]+") || value.length() > 5 || Integer.parseInt(value) < minValue) {
			throw new IdentityBrokerException("Bad value for attribute '" + name + "' in header : " + config)
					.withMessageCode(BAD_PLACEMENT_COORDINATES);
		}
		return Integer.parseInt(value);
	}

	private static String getSignatureHeader(HttpHeaders headers, String name, String defaultValue) {
		Optional<String> headerValue = headers.firstValue(name);
		if (headerValue.isPresent() && !headerValue.get().isBlank()) {
			return headerValue.get();
		}
		return defaultValue;
	}
}