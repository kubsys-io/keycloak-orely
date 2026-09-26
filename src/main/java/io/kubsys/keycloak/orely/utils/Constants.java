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

public interface Constants {

	// JSON context attributes
	String ORELY_CONTEXT = "orely_context";
	String CONTEXT_FORCE_AUTHN = "force_authn";
	String CONTEXT_ATTRIBUTES = "attributes";
	String CONTEXT_REQUESTED = "requested";
	String CONTEXT_REQUESTED_NAME = "name";
	String CONTEXT_REQUESTED_REQUIRED = "required";
	String CONTEXT_SIGNATURE = "signature";
	String CONTEXT_CHALLENGE = "challenge";
	String CONTEXT_TITLE = "title";
	String CONTEXT_KEY_VALUES = "key_values";
	String CONTEXT_KEY_NAME = "key";
	String CONTEXT_VALUE_NAME = "value";
	String CONTEXT_COLOR_NAME = "color";
	String CONTEXT_TSP_MODE = "TSP-Mode";
	String CONTEXT_TSP_ID = "TSP-ID";
	String CONTEXT_MIN_QAA = "MinQAA";
	String CONTEXT_SUBJECT_ID = "Subject-ID";
	String CONTEXT_LANG = "lang";
	String CONTEXT_SSO_MAX_NB = "SSO-MaxNb";
	String CONTEXT_SSO_TIMEOUT = "SSO-Timeout";
	String FULL_CERTIFICATE = "fullCertificate";
	String CONTEXT_DOCUMENT_DOWNLOAD_PATH = "document_download_path";
	String CONTEXT_DOCUMENT_UPLOAD_PATH = "document_upload_path";

	// Challenge values
	String CHALLENGE_TYPE_VALUE = "VASCO";
	String CHALLENGE_VERSION_VALUE = "1.0";
	String CHALLENGE_OPERATION_AUTH = "AUTH";
	String CHALLENGE_OPERATION_SIGN = "SIGN";

	// Fieldname values
	String HEADER_SIGNATURE_PLACEMENT = "orely-sign-placement";
	String FIELD_NAME = "fieldname";
	String WATERMARK = "watermark";
	String PLACEMENT_X = "x";
	String PLACEMENT_Y = "y";
	String PLACEMENT_WIDTH = "w";
	String PLACEMENT_HEIGHT = "h";
	String PLACEMENT_PAGE = "p";
	String HEADER_SIGN_POLICY = "orely-sign-policy";
	String HEADER_SIGN_QAA = "orely-sign-qaa";
	String HEADER_SIGN_FORM = "orely-sign-form";
	String HEADER_SIGN_COMMITMENT = "orely-sign-commitment";

	// Electronic Signature
	String SIGN_FULLY_DELEGATED = "urn:oid:1.3.171.1.4.1.1.1";
	String SIGN_PARTIALLY_DELEGATED = "urn:oid:1.3.171.1.4.1.3.1";
	String SIGNATURE_QAA_ADES = "AdES"; // Advanced Electronic Signature
	String SIGNATURE_QAA_ADES_QC = "AdES+QC"; // Advanced Electronic Signature with Qualified Certificate
	String SIGNATURE_QAA_QES = "QES"; // Qualified Electronic Signature
	String SIGN_FORM_T = "urn:luxtrust:names:dss:1.0:profiles:PAdES:forms:T"; // Timestamp (Default)
	String SIGN_FORM_LT = "urn:luxtrust:names:dss:1.0:profiles:PAdES:forms:LT"; // Long-Term
	String SIGN_FORM_EPES = "urn:luxtrust:names:dss:1.0:profiles:PAdES:forms:EPES"; // Explicit Policy-based
	String SIGN_COMMITMENT_APPROVAL = "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval"; // Default
	String SIGN_COMMITMENT_ORIGIN = "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin";
	String SIGN_COMMITMENT_RECEIPT = "http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt";
	String SIGN_COMMITMENT_DELIVERY = "http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery";
	String SIGN_COMMITMENT_SENDER = "http://uri.etsi.org/01903/v1.2.2#ProofOfSender";
	String SIGN_COMMITMENT_CREATION = "http://uri.etsi.org/01903/v1.2.2#ProofOfCreation";

	// SAML attributes
	String ORELY_PORTAL_URL_SIMULATOR = "https://mock.test.luxtrust.com/FederatedServiceFrontEnd/saml/";
	String ORELY_PORTAL_URL_TEST = "https://orely.test.luxtrust.com/FederatedServiceFrontEnd/saml/";
	String ORELY_PORTAL_URL_PRODUCTION = "https://orely.luxtrust.com/FederatedServiceFrontEnd/saml/";
	String LUXTRUST_ASSERTION_NAMESPACE = "urn:lu:luxtrust:names:tc:SAML:2.0:assertion";
	String LUXTRUST_PROTOCOL_NAMESPACE = "urn:lu:luxtrust:names:tc:SAML:2.0:protocol";
	String LUXTRUST_ATTRIBUTE_NAMESPACE = "urn:luxtrust:names:tc:SAML:2.0:attribute:";
	String LUXTRUST_REQUESTED_ATTRIBUTE_NAMESPACE = "luxtrust:RequestedAttribute";
	String LUXTRUST_NAMESPACE_PREFIX = "luxtrust:";
	String LUXTRUST_QUALIFIED_NAME = "xmlns:luxtrust";
	String SAML_CHALLENGE_NAME = "Challenge";
	String SAML_ASSERTION_NAME = "Name";
	String SAML_ATTRIBUTE_VALUE = "AttributeValue";
	String SAML_ASSERTION_NAME_FORMAT = "NameFormat";
	String SAML_ASSERTION_IS_REQUIRED = "isRequired";
	String DSS_SIGNATURE_REQUEST = "DSSRequest";

	// X.509 Principal names
	String X500_SERIAL_NUMBER = "SERIALNUMBER";
	String X500_COUNTRY = "C";
	String X500_COMMON_NAME = "CN";
	String X500_SURNAME = "SURNAME";
	String X500_GIVENNAME = "GIVENNAME";
	String X500_TITLE = "T";
	String X500_E = "E";
	String X500_EMAIL = "EMAIL";
	String X500_EMAILADDRESS = "EMAILADDRESS";

	// Claim names
	String CLAIM_SUBJECT_PREFIX = "luxtrust_";
	String CLAIM_SUBJECT_TYPE = "luxtrust_type";
	String CLAIM_SUBJECT_COMMON_NAME = "luxtrust_common_name";
	String CLAIM_SUBJECT_COUNTRY = "luxtrust_country";
	String CLAIM_CERTIFICATE_SERIAL_NUMBER = "luxtrust_certificate_serial";
	String CLAIM_CERTIFICATE_NOT_BEFORE = "luxtrust_certificate_not_before";
	String CLAIM_CERTIFICATE_NOT_AFTER = "luxtrust_certificate_not_after";
	String CLAIM_CERTIFICATE_ISSUER = "luxtrust_certificate_issuer";
	String CLAIM_CERTIFICATE_THUMBPRINT = "luxtrust_certificate_thumbprint";

	// Keycloak console fields
	String ORELY_PRODUCTION = "orelyProduction";
	String ISSUER_NAME = "issuerName";
	String PROVIDER_NAME = "providerName";
	String VALIDATION_CERTIFICATE = "validationCertificate";
	String VALIDATION_CERTIFICATE_SUBJECT = "validationCertificateSubject";
	String VALIDATION_CERTIFICATE_ISSUER = "validationCertificateIssuer";
	String VALIDATION_CERTIFICATE_DATES = "validationCertificateDates";
	String FAKE_VALIDATION_CERTIFICATE = "fakeValidationCertificate";
	String CHALLENGE_TYPE = "challengeType";
	String CHALLENGE_VERSION = "challengeVersion";
	String CHALLENGE_AUTHENTICATION = "challengeAuthentication";
	String CHALLENGE_SIGNATURE = "challengeSignature";
	String DOCUMENT_SERVER_TIMEOUT = "documentServerTimeout";
	String DOCUMENT_BASE_URL = "documentBaseUrl";
	String X500_PRINCIPAL = "x500Principal";
	String MOCK_PRINCIPAL_VALUE = "SERIALNUMBER=09965086505074541334, GIVENNAME=Marie, SURNAME=Curie, CN=Marie Curie, C=FR, EMAILADDRESS=marie.curie@exemple.com, T=Private Person";

	// HTTP Protocol headers management
	String HTTP_HEADER_ACCEPT = "Accept";
	String HTTP_HEADER_USER_AGENT = "User-Agent";
	String HTTP_HEADER_CONTENT_TYPE = "Content-Type";
	String MIME_TYPE_APPLICATION_PDF = "application/pdf";
	String HTTP_HEADER_X_CORRELATION_ID = "X-Correlation-ID";
	String HTTP_HEADER_DSS_RESULT_MAJOR = "X-DSS-Result-Major";
	String HTTP_HEADER_DSS_RESULT_MINOR = "X-DSS-Result-Minor";
	String HTTP_HEADER_DSS_RESULT_MESSAGE = "X-DSS-Result-Message";

}
