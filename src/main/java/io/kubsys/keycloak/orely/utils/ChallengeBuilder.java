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
package io.kubsys.keycloak.orely.utils;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds the Orely challenge structure that will be Base64 encoded as a SAML
 * request extension.
 * <p>
 * This builder generates an XML payload tailored for VASCO tokens. It
 * automatically truncates the content to comply with the device's maximum
 * display
 * capacity.
 * </p>
 */
public class ChallengeBuilder {

	private static final int CHALLENGE_MAX_SIZE = 111;

	final String type;
	final String version;
	final String operation;
	final List<Pair> values = new ArrayList<>();
	String title = "";

	/**
	 * Initializes a new challenge builder for a specific operation.
	 *
	 * @param type      The type (e.g., "VASCO").
	 * @param version   The versio type (e.g., "1.0").
	 * @param operation The operation type (e.g., "AUTH" or "SIGN").
	 */
	protected ChallengeBuilder(String type, String version, String operation) {
		this.type = type;
		this.version = version;
		this.operation = operation;
	}

	public static ChallengeBuilder of(String type, String version, String operation) {
		return new ChallengeBuilder(type, version, operation);
	}

	/**
	 * Sets the main title of the challenge displayed on the user's device.
	 *
	 * @param title The challenge title. Null is safely converted to an empty
	 *              string.
	 * @return The current builder instance.
	 */
	public ChallengeBuilder withTitle(String title) {
		this.title = title == null ? "" : title;
		return this;
	}

	public ChallengeBuilder withPair(String key, String value) {
		return withPair(key, value, "default");
	}

	public ChallengeBuilder withPair(String key, String value, String color) {
		return withPair(new Pair(key, value, color));
	}

	public ChallengeBuilder withPair(Pair pair) {
		values.add(pair);
		return this;
	}

	public boolean isEmpty() {
		if (title != null && !title.isBlank()) {
			return false;
		}
		return values.isEmpty();
	}

	/**
	 * Builds and serializes the challenge into an XML string.
	 * <p>
	 * The content is normalized (truncated if exceeding hardware constraints)
	 * and XML-escaped to prevent malformed payloads.
	 * </p>
	 *
	 * @return The XML representation of the challenge.
	 */
	/**
	 * Builds and serializes the challenge into an XML string using the DOM API.
	 * <p>
	 * The content is normalized (truncated if exceeding hardware constraints)
	 * and natively XML-escaped by the DOM implementation to prevent malformed
	 * payloads.
	 * </p>
	 *
	 * @return The XML representation of the challenge.
	 */
	public String build() {
		normalize();

		try {
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			Document doc = docBuilder.newDocument();

			// Élément racine
			Element rootElement = doc.createElement("ChallengeStructure");
			doc.appendChild(rootElement);

			// Type
			Element typeElement = doc.createElement("Type");
			typeElement.setTextContent(type);
			rootElement.appendChild(typeElement);

			// Version
			Element versionElement = doc.createElement("Version");
			versionElement.setTextContent(version);
			rootElement.appendChild(versionElement);

			// Operation
			Element operationElement = doc.createElement("Operation");
			operationElement.setTextContent(operation);
			rootElement.appendChild(operationElement);

			// Title
			Element titleElement = doc.createElement("Title");
			titleElement.setTextContent(title != null ? title : "");
			rootElement.appendChild(titleElement);

			// KeyValues
			if (!values.isEmpty()) {
				Element keyValuesElement = doc.createElement("KeyValues");
				for (Pair pair : values) {
					if (pair.key() == null || pair.key().isBlank() || pair.value() == null || pair.value().isBlank()) {
						continue;
					}

					Element keyValueElement = doc.createElement("KeyValue");

					Element keyElement = doc.createElement("Key");
					keyElement.setTextContent(pair.key());
					keyValueElement.appendChild(keyElement);

					Element valueElement = doc.createElement("Value");
					valueElement.setTextContent(pair.value());
					if (pair.color() != null && !pair.color().isBlank()) {
						valueElement.setAttribute("color", pair.color());
					}
					keyValueElement.appendChild(valueElement);

					keyValuesElement.appendChild(keyValueElement);
				}

				if (keyValuesElement.hasChildNodes()) {
					rootElement.appendChild(keyValuesElement);
				}
			}

			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));

			return writer.toString();

		} catch (Exception e) {
			throw new RuntimeException("Error while building the XML Challenge payload", e);
		}
	}

	/**
	 * Normalizes the payload size to prevent exceeding the maximum allowed size for
	 * the device. Truncates pairs from the end if the total size goes beyond
	 * {@link #CHALLENGE_MAX_SIZE}.
	 */
	private void normalize() {
		title = title != null ? title : "";

		int currentSize = getEncodedSize(title) + 2;
		if (currentSize > CHALLENGE_MAX_SIZE) {
			clear();
		}

		for (int i = 0; i < values.size(); i++) {
			Pair pair = values.get(i);
			currentSize += getEncodedSize(pair.key());
			currentSize += getEncodedSize(pair.value());
			if (currentSize > CHALLENGE_MAX_SIZE) {
				clearKeys(i);
				break;
			}
		}
	}

	/**
	 * Calculates the visual/encoded footprint of a string based on VASCO display
	 * limitations.
	 */
	private int getEncodedSize(String value) {
		int length = 1;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
					|| c == ' ' || c == '.' || c == '\t' || c == '\n') {
				length += 1;
			} else {
				length += 3;
			}
		}
		return length;
	}

	private void clear() {
		title = "";
		clearKeys(0);
	}

	private void clearKeys(int index) {
		int currentIndex = values.size() - 1;
		while (currentIndex >= index) {
			values.remove(currentIndex--);
		}

		if (values.isEmpty()) {
			withPair("", "");
		}
	}

	/**
	 * Represents a key-value pair used in the challenge.
	 *
	 * @param key   The challenge parameter name.
	 * @param value The challenge parameter value.
	 * @param color The optional color formatting for the value.
	 */
	public record Pair(String key, String value, String color) {
	}
}