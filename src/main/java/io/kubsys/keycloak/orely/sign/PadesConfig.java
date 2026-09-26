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
import java.net.URISyntaxException;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

import io.kubsys.keycloak.orely.BaseConfig;

public class PadesConfig extends BaseConfig {

	public PadesConfig() {
		super();
	}

	public PadesConfig(IdentityProviderModel model) {
		super(model);
	}

	@Override
	public String getPortalUrl() {
		boolean isProd = Boolean.parseBoolean(getConfig().get(ORELY_PRODUCTION));
		String baseUrl = isProd ? ORELY_PORTAL_URL_PRODUCTION : ORELY_PORTAL_URL_TEST;
		baseUrl += "dss/req";
		return baseUrl;
	}

	@Override
	public final String getChallengeOperation() {
		return getConfig().get(CHALLENGE_SIGNATURE);
	}

	public final int getDocumentServerTimeout() {
		return Integer.parseInt(getConfig().get(DOCUMENT_SERVER_TIMEOUT));
	}

	public final String getDocumentBaseUrl() {
		return getConfig().get(DOCUMENT_BASE_URL);
	}

	public final String getDocumentUrl(String documentPath) {
		return getDocumentBaseUrl() + documentPath;
	}

	@Override
	public void validate(RealmModel realm) {
		super.validate(realm);
		String timeout = getConfig().get(DOCUMENT_SERVER_TIMEOUT);
		if (timeout == null || timeout.isBlank()) {
			throw new IllegalArgumentException("The document download timeout is mandatory");
		}
		if (!timeout.matches("[0-9]+")) {
			throw new IllegalArgumentException("Expect non negative integer value for document download timeout");
		}

		String documentBaseUrl = getDocumentBaseUrl();
		if (documentBaseUrl == null || documentBaseUrl.isBlank()) {
			throw new IllegalArgumentException("Document Upload URL is mandatory");
		}
		validateDocumentBaseUrl(documentBaseUrl);
	}

	private void validateDocumentBaseUrl(String url) {

		try {
			if (url.endsWith("/")) {
				url = url.substring(0, url.length() - 1);
				getConfig().put(DOCUMENT_BASE_URL, url);
			}
			URI uri = new URI(url);
			String scheme = uri.getScheme();
			if (scheme == null ||
					(!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
				throw new IllegalArgumentException("The document base URL  must use http:// or https:// scheme.");
			}
			if (uri.getHost() == null || uri.getHost().isBlank()) {
				throw new IllegalArgumentException("The document base URL  must contain a valid host.");
			}
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("The document base URL  is not a valid URL.");
		}
	}

}