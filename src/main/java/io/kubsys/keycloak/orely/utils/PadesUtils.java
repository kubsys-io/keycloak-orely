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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.keycloak.broker.provider.IdentityBrokerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import io.kubsys.keycloak.orely.sign.PadesFactory;

/**
 * Utility class providing helper methods for the Orely signature integration.
 * Includes methods for certificate normalization and OASIS DSS XML request
 * generation.
 */
public class PadesUtils implements ErrorCodes, Constants {

	// Standard W3C Namespaces
	public static final String NS_XSI = "http://www.w3.org/2001/XMLSchema-instance";
	public static final String NS_XMLNS = "http://www.w3.org/2000/xmlns/";

	// Core DSS Namespaces
	public static final String NS_DSS = "urn:oasis:names:tc:dss:1.0:core:schema";
	public static final String NS_LUXTRUST_DSS = "urn:luxtrust:names:dss:1.0:core:schema#";
	public static final String DSS_NS = "urn:oasis:names:tc:dss:1.0:core:schema";
	public static final String DSS_RESULT_MAJOR_PREFIX = "urn:oasis:names:tc:dss:1.0:resultmajor:";
	public static final String DSS_RESULT_MINOR_PREFIX = "urn:oasis:names:tc:dss:1.0:resultminor:";
	public static final String DSS_SUCCESS_STATUS = "Success";

	// Profiles and Policies Namespaces
	public static final String NS_SIG_POL = "urn:oasis:names:tc:dss-x:1.0:profiles:SignaturePolicy:schema#";
	public static final String NS_ADES = "urn:oasis:names:tc:dss:1.0:profiles:AdES:schema#";
	public static final String NS_XADES = "http://uri.etsi.org/01903/v1.3.2#";
	public static final String NS_VIS_SIG = "urn:oasis:names:tc:dssx:1.0:profiles:VisibleSignatures:schema#";

	// Common Identifiers
	public static final String PROFILE_PADES = "urn:luxtrust:names:dss:1.0:profiles:PAdES";
	public static final String IDENTIFIER_COMMITMENT_TYPE = "urn:oasis:names:tc:dss:1.0:profiles:XAdES:CommitmentTypeIndication";

	public record SignaturePlacement(Integer x, Integer y, Integer width, Integer height, Integer page,
			String fieldName, byte[] watermarkBytes) {
	}

	/**
	 * Generates an OASIS DSS (Digital Signature Service) XML SignRequest payload
	 * to request a PAdES signature for a given PDF document.
	 */
	public static String generateSignatureRequest(String signaturePolicy, String signatureQAA,
			String signatureForm, String commitmentType, SignaturePlacement signaturePlacement, byte[] pdfBytes) {
		try {
			Objects.requireNonNull(signaturePolicy);
			Objects.requireNonNull(signatureForm);
			Objects.requireNonNull(commitmentType);
			Objects.requireNonNull(pdfBytes);

			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			Document doc = dbf.newDocumentBuilder().newDocument();

			Element root = doc.createElementNS(NS_DSS, "dss:SignRequest");
			root.setAttribute("Profile", PROFILE_PADES);
			doc.appendChild(root);

			// Optional Inputs
			Element optionalInputs = doc.createElementNS(NS_DSS, "dss:OptionalInputs");

			// Signature policy
			Element genPolicy = doc.createElementNS(NS_SIG_POL, "dsssigpol:GenerateUnderSignaturePolicy");
			Element policyId = doc.createElementNS(NS_SIG_POL, "dsssigpol:SignaturePolicyIdentifier");
			policyId.setTextContent(signaturePolicy);
			genPolicy.appendChild(policyId);
			optionalInputs.appendChild(genPolicy);

			// Signature QAA
			if (signatureQAA != null && !signatureQAA.isBlank()) {
				Element signatureQaaEelement = doc.createElementNS(NS_LUXTRUST_DSS, "luxtrustdss:SignatureQAA");
				signatureQaaEelement.setTextContent(signatureQAA);
				optionalInputs.appendChild(signatureQaaEelement);
			}

			// Signature form
			Element signatureFormElement = doc.createElementNS(NS_ADES, "dssades:SignatureForm");
			signatureFormElement.setTextContent(signatureForm);
			optionalInputs.appendChild(signatureFormElement);

			// Properties (Commitment Type)
			Element properties = doc.createElementNS(NS_DSS, "dss:Properties");
			Element signedProperties = doc.createElementNS(NS_DSS, "dss:SignedProperties");
			Element property = doc.createElementNS(NS_DSS, "dss:Property");
			Element identifier = doc.createElementNS(NS_DSS, "dss:Identifier");
			identifier.setTextContent(IDENTIFIER_COMMITMENT_TYPE);

			Element value = doc.createElementNS(NS_DSS, "dss:Value");
			Element reqCommitment = doc.createElementNS(NS_ADES, "dssades:RequestedCommitmentTypeIndication");
			Element commitmentTypeIndication = doc.createElementNS(NS_XADES, "xades:CommitmentTypeIndication");
			Element commitmentTypeId = doc.createElementNS(NS_XADES, "xades:CommitmentTypeId");
			Element xadesIdentifier = doc.createElementNS(NS_XADES, "xades:Identifier");
			xadesIdentifier.setTextContent(commitmentType);
			Element allSignedDataObjects = doc.createElementNS(NS_XADES, "xades:AllSignedDataObjects");

			commitmentTypeId.appendChild(xadesIdentifier);
			commitmentTypeIndication.appendChild(commitmentTypeId);
			commitmentTypeIndication.appendChild(allSignedDataObjects);
			reqCommitment.appendChild(commitmentTypeIndication);
			value.appendChild(reqCommitment);
			property.appendChild(identifier);
			property.appendChild(value);
			signedProperties.appendChild(property);
			properties.appendChild(signedProperties);
			optionalInputs.appendChild(properties);

			// Signature position
			Element visSigConfig = doc.createElementNS(NS_VIS_SIG, "dssvissig:VisibleSignatureConfiguration");
			visSigConfig.setAttributeNS(NS_XMLNS, "xmlns:dssvissig", NS_VIS_SIG);
			visSigConfig.setAttributeNS(NS_XMLNS, "xmlns:xsi", NS_XSI);

			Element visSigPolicy = doc.createElementNS(NS_VIS_SIG, "dssvissig:VisibleSignaturePolicy");
			visSigPolicy.setTextContent("GeneralPolicy");
			visSigConfig.appendChild(visSigPolicy);

			if (signaturePlacement != null) {

				if (signaturePlacement.fieldName() != null && !signaturePlacement.fieldName().isBlank()) {
					Element fieldName = doc.createElementNS(NS_VIS_SIG, "dssvissig:FieldName");
					fieldName.setTextContent(signaturePlacement.fieldName());
					visSigConfig.appendChild(fieldName);
				}

				boolean hasPlacementPosition = signaturePlacement.x() != null && signaturePlacement.y() != null
						&& signaturePlacement.width() != null && signaturePlacement.height() != null
						&& signaturePlacement.page() != null;
				boolean hasWatermark = signaturePlacement.watermarkBytes() != null;

				if (hasPlacementPosition || hasWatermark) {
					Element visSigPos = doc.createElementNS(NS_VIS_SIG, "dssvissig:VisibleSignaturePosition");
					visSigPos.setAttributeNS(NS_XSI, "xsi:type", "dssvissig:GeneralVisibleSignaturePositionType");
					if (hasPlacementPosition) {
						Element pageNumberElement = doc.createElementNS(NS_VIS_SIG, "dssvissig:PageNumber");
						pageNumberElement.setTextContent(String.valueOf(signaturePlacement.page()));
						visSigPos.appendChild(pageNumberElement);

						Element xElement = doc.createElementNS(NS_VIS_SIG, "dssvissig:x");
						xElement.setTextContent(signaturePlacement.x() + "pt");
						visSigPos.appendChild(xElement);

						Element yElement = doc.createElementNS(NS_VIS_SIG, "dssvissig:y");
						yElement.setTextContent(signaturePlacement.y() + "pt");
						visSigPos.appendChild(yElement);

						Element width = doc.createElementNS(NS_VIS_SIG, "dssvissig:Width");
						width.setTextContent(signaturePlacement.width() + "pt");
						visSigPos.appendChild(width);

						Element height = doc.createElementNS(NS_VIS_SIG, "dssvissig:Height");
						height.setTextContent(signaturePlacement.height() + "pt");
						visSigPos.appendChild(height);
					}
					if (hasWatermark) {
						Element visSigItemsConfig = doc.createElementNS(NS_VIS_SIG,
								"dssvissig:VisibleSignatureItemsConfiguration");
						Element visSigItem = doc.createElementNS(NS_VIS_SIG, "dssvissig:VisibleSignatureItem");
						Element itemName = doc.createElementNS(NS_VIS_SIG, "dssvissig:ItemName");
						itemName.setTextContent("SignerImage");
						visSigItem.appendChild(itemName);

						Element itemValue = doc.createElementNS(NS_VIS_SIG, "dssvissig:ItemValue");
						itemValue.setAttributeNS(NS_XSI, "xsi:type", "dssvissig:ItemValueImageType");
						Element base64Data = doc.createElementNS(NS_DSS, "dss:Base64Data");
						base64Data.setTextContent(
								Base64.getEncoder().encodeToString(signaturePlacement.watermarkBytes()));
						itemValue.appendChild(base64Data);

						visSigItem.appendChild(itemValue);
						visSigItemsConfig.appendChild(visSigItem);
						visSigConfig.appendChild(visSigItemsConfig);
					}
					visSigConfig.appendChild(visSigPos);
				}
			}

			Element other = doc.createElementNS(NS_VIS_SIG, "dssvissig:other");
			visSigConfig.appendChild(other);
			optionalInputs.appendChild(visSigConfig);

			doc.getDocumentElement().appendChild(optionalInputs);

			// Document bytes
			Element inputDocuments = doc.createElementNS(NS_DSS, "dss:InputDocuments");
			Element document = doc.createElementNS(NS_DSS, "dss:Document");
			Element base64PdfData = doc.createElementNS(NS_DSS, "dss:Base64Data");
			base64PdfData.setAttribute("MimeType", "application/pdf");
			base64PdfData.setTextContent(Base64.getEncoder().encodeToString(pdfBytes));

			document.appendChild(base64PdfData);
			inputDocuments.appendChild(document);
			root.appendChild(inputDocuments);

			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			return writer.toString();
		} catch (Exception e) {
			throw new IdentityBrokerException(
					"Unable to build signature request. " + e.getMessage())
					.withMessageCode(SIGN_REQUEST_BUILDER_ERROR);
		}
	}

	public record SignatureResult(
			String resultMajor,
			String resultMinor,
			String resultMessage,
			byte[] signedDocument) {
	}

	public static SignatureResult parseDssResponse(String encodedXmlContent) {

		try {
			if (encodedXmlContent == null || encodedXmlContent.isBlank()) {
				throw new IllegalArgumentException("Le contenu XML fourni est vide ou null");
			}
			byte[] documentBytes = Base64.getDecoder().decode(encodedXmlContent);

			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new ByteArrayInputStream(documentBytes));

			// Extract result
			String resultMajor = getTextContentNS(doc, "ResultMajor");
			if (resultMajor == null || resultMajor.isBlank()) {
				throw new IllegalStateException("Missing mandatory field ResultMajor");
			}
			resultMajor = resultMajor.replace(DSS_RESULT_MAJOR_PREFIX, "");

			String resultMinor = getTextContentNS(doc, "ResultMinor");
			if (resultMinor != null) {
				resultMinor = resultMinor.replace(DSS_RESULT_MINOR_PREFIX, "");
			}
			String resultMessage = getTextContentNS(doc, "ResultMessage");
			byte[] pdfBytes = null;

			if (DSS_SUCCESS_STATUS.equals(resultMajor)) {
				NodeList signaturePtrList = doc.getElementsByTagNameNS(DSS_NS, "SignaturePtr");
				if (signaturePtrList.getLength() > 0) {
					Element signaturePtr = (Element) signaturePtrList.item(0);
					String documentId = signaturePtr.getAttribute("WhichDocument");

					NodeList documentList = doc.getElementsByTagNameNS(DSS_NS, "Document");
					for (int i = 0; i < documentList.getLength(); i++) {
						Element documentElement = (Element) documentList.item(i);

						if (documentId.equals(documentElement.getAttribute("ID"))) {
							NodeList base64DataList = documentElement.getElementsByTagNameNS(DSS_NS, "Base64Data");
							if (base64DataList.getLength() > 0) {
								Element base64Element = (Element) base64DataList.item(0);
								String base64String = base64Element.getTextContent().replaceAll("\\s", "");
								pdfBytes = Base64.getDecoder().decode(base64String);
							}
							break;
						}
					}
				}
				if (pdfBytes == null) {
					throw new IllegalStateException("Missing signed document bytes with status " + DSS_SUCCESS_STATUS);
				}
			}

			return new SignatureResult(resultMajor, resultMinor, resultMessage, pdfBytes);

		} catch (Exception e) {
			String errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
			return new SignatureResult("Error", null, errorMsg, null);
		}
	}

	private static String getTextContentNS(Document doc, String localName) {
		NodeList list = doc.getElementsByTagNameNS(DSS_NS, localName);
		if (list != null && list.getLength() > 0) {
			return list.item(0).getTextContent();
		}
		return null;
	}

	public static void uploadPdfToClient(String uploadUrl, String customUserAgent, String flowId,
			Duration connectTimeout, SignatureResult signatureResult) throws Exception {

		HttpClient sharedClient = PadesFactory.getSharedHttpClient();

		byte[] documentBytes = signatureResult.signedDocument();
		if (documentBytes == null) {
			documentBytes = new byte[0];
		}
		HttpRequest.Builder builder = HttpRequest.newBuilder()
				.uri(URI.create(uploadUrl))
				.header(HTTP_HEADER_USER_AGENT, customUserAgent)
				.header(HTTP_HEADER_X_CORRELATION_ID, flowId)
				.header(HTTP_HEADER_CONTENT_TYPE, MIME_TYPE_APPLICATION_PDF)
				.POST(HttpRequest.BodyPublishers.ofByteArray(documentBytes));
		if (signatureResult.resultMajor() != null && !signatureResult.resultMajor().isBlank()) {
			builder.header(HTTP_HEADER_DSS_RESULT_MAJOR, signatureResult.resultMajor());
		}
		if (signatureResult.resultMinor() != null && !signatureResult.resultMinor().isBlank()) {
			builder.header(HTTP_HEADER_DSS_RESULT_MINOR, signatureResult.resultMinor());
		}
		if (signatureResult.resultMessage() != null && !signatureResult.resultMessage().isBlank()) {
			builder.header(HTTP_HEADER_DSS_RESULT_MESSAGE, signatureResult.resultMessage());
		}
		if (connectTimeout != null) {
			builder.timeout(connectTimeout);
		}

		HttpRequest httpRequest = builder.build();
		HttpResponse<String> response = sharedClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() < 200 || response.statusCode() >= 300) {
			throw new RuntimeException("Failed to upload signed document. HTTP Status: " + response.statusCode());
		}
	}
}