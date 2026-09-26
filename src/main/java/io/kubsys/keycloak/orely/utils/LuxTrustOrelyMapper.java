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
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.jboss.logging.Logger;
import org.jboss.logging.MDC;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;

import io.kubsys.keycloak.orely.utils.PadesUtils.SignatureResult;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

/**
 * Keycloak Identity Provider Mapper for LuxTrust SAML responses.
 * <p>
 * This mapper performs two main extraction tasks to synchronize user profiles:
 * <ul>
 * <li>Intercepts the SAML NameID (expected to be an X.509 Subject Name), parses
 * its Relative Distinguished Names (RDN), and maps them to Keycloak user
 * attributes.
 * Specifically, it extracts the {@code SERIALNUMBER} to use as the permanent
 * broker user ID and local username, ensuring identity stability across
 * certificate renewals.</li>
 * <li>Extracts additional SAML attributes from the assertion statements,
 * filters them by the LuxTrust namespace, and maps them dynamically to the
 * Keycloak user profile.</li>
 * </ul>
 * </p>
 */
public class LuxTrustOrelyMapper extends AbstractIdentityProviderMapper implements Constants, ErrorCodes {

    private static final int KEYCLOAK_NAME_MAX_LENGTH = 255;
    private static final int KEYCLOAK_VALUE_MAX_LENGTH = 2048;

    private static final Logger logger = Logger.getLogger(LuxTrustOrelyMapper.class);

    private static final Set<IdentityProviderSyncMode> COMPATIBLE_SYNC_MODES = Set.of(
            IdentityProviderSyncMode.IMPORT,
            IdentityProviderSyncMode.LEGACY,
            IdentityProviderSyncMode.FORCE);

    @Override
    public final String[] getCompatibleProviders() {
        return new String[] { "luxtrust-orely-authn", "luxtrust-orely-signature",
                "luxtrust-orely-authn-simulator", "luxtrust-orely-signature-simulator" };
    }

    @Override
    public final String getId() {
        return "luxtrust-orely-saml-mapper";
    }

    @Override
    public final String getDisplayCategory() {
        return "Preprocessor";
    }

    @Override
    public final String getDisplayType() {
        return "LuxTrust Attribute Importer";
    }

    @Override
    public final String getHelpText() {
        return "Extracts both NameID (X509 Subject Name) RDNs and assertion attributes, using SERIALNUMBER as the primary Username.";
    }

    @Override
    public final List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<>();
    }

    @Override
    public final boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return COMPATIBLE_SYNC_MODES.contains(syncMode);
    }

    /**
     * Triggered during the first login of a user (First Broker Login flow) and
     * prior to any user update.
     * <p>
     * Parses the incoming SAML assertion and populates the brokered identity
     * context with the extracted attributes. This pre-filled context is then used
     * by Keycloak to either create a new user or update an existing one.
     * </p>
     *
     * @param session     The current Keycloak session.
     * @param realm       The realm in which the login is occurring.
     * @param mapperModel The mapper configuration.
     * @param context     The brokered identity context holding the SAML response
     *                    and assertions.
     */
    @Override
    public final void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String flowId = "unknown-flow";
        if (authSession != null && authSession.getParentSession() != null) {
            flowId = authSession.getParentSession().getId();
        }
        String idpAlias = context.getIdpConfig().getAlias();
        MDC.put("realm", realm.getName());
        MDC.put("flowId", flowId);
        MDC.put("phase", "broker_response");
        try {
            parseAndMapSubject(context);
            parseAndMapAssertions(context, flowId, idpAlias, realm.getName());
        } finally {
            MDC.remove("realm");
            MDC.remove("flowId");
            MDC.remove("phase");
        }
    }

    /**
     * Triggered on subsequent logins for returning users.
     * <p>
     * Synchronizes the existing Keycloak user profile with the latest data from the
     * LuxTrust SAML response. To optimize performance and prevent redundant XML
     * parsing, this method directly transfers the attributes already extracted into
     * the context by
     * {@link #preprocessFederatedIdentity(KeycloakSession, RealmModel, IdentityProviderMapperModel, BrokeredIdentityContext)}.
     * </p>
     *
     * @param session     The current Keycloak session.
     * @param realm       The realm in which the login is occurring.
     * @param user        The existing Keycloak user model to update.
     * @param mapperModel The mapper configuration.
     * @param context     The brokered identity context pre-populated with SAML
     *                    attributes.
     */
    @Override
    public final void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String flowId = "unknown-flow";
        if (authSession != null && authSession.getParentSession() != null) {
            flowId = authSession.getParentSession().getId();
        }
        String idpAlias = context.getIdpConfig().getAlias();
        MDC.put("realm", realm.getName());
        MDC.put("flowId", flowId);
        MDC.put("phase", "broker_response");
        try {
            parseAndMapSubject(context);
            parseAndMapAssertions(context, flowId, idpAlias, realm.getName());
        } finally {
            MDC.remove("realm");
            MDC.remove("flowId");
            MDC.remove("phase");
        }

        for (Map.Entry<String, List<String>> entry : context.getAttributes().entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (values != null && !values.isEmpty()) {
                user.setSingleAttribute(key, values.getFirst());
            }
        }
    }

    /**
     * Parses the X.509 Subject Name from the context's assertion and applies the
     * RDN values to the brokered identity context.
     *
     * @param context The current brokered identity context containing the raw
     *                NameID.
     */
    private void parseAndMapSubject(BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        if (assertion == null || assertion.getSubject() == null || assertion.getSubject().getSubType() == null) {
            logger.warn("Unable to extract Subject from SAML assertion");
            return;
        }
        String nameId = null;
        Object baseId = assertion.getSubject().getSubType().getBaseID();
        if (baseId instanceof NameIDType) {
            nameId = ((NameIDType) baseId).getValue();
        }
        if (nameId == null || nameId.isBlank()) {
            logger.warn("Unable to find NameID in assertion Subject");
            return;
        }

        try {
            LdapName ldapName = new LdapName(nameId);
            for (Rdn rdn : ldapName.getRdns()) {
                String key = rdn.getType().toUpperCase();
                String value = String.valueOf(rdn.getValue()).trim();

                String cleanName = CLAIM_SUBJECT_PREFIX + key.toLowerCase().replace('-', '_');
                if (cleanName.length() > KEYCLOAK_NAME_MAX_LENGTH) {
                    // Name too big to fit in database. Ignore and notify
                    logger.warnf("Ignore attribute %s because name length %d exceeds maximum (%d characters)",
                            cleanName, cleanName.length(), KEYCLOAK_NAME_MAX_LENGTH);
                    continue;
                }

                if (value.length() > KEYCLOAK_VALUE_MAX_LENGTH) {
                    // Value too big to fit in database. Ignore and notify
                    logger.warnf("Ignore attribute %s because value length %d exceeds maximum (%d characters)",
                            cleanName, value.length(), KEYCLOAK_VALUE_MAX_LENGTH);
                    continue;
                }
                switch (key) {
                    case X500_TITLE:
                        context.setUserAttribute(CLAIM_SUBJECT_TYPE, value);
                        logger.debugf("Set %s to %s", CLAIM_SUBJECT_TYPE, value);
                        break;
                    case X500_COMMON_NAME:
                        context.setUserAttribute(CLAIM_SUBJECT_COMMON_NAME, value);
                        logger.debugf("Set %s to %s", CLAIM_SUBJECT_COMMON_NAME, Utils.maskName(value));
                        break;
                    case X500_COUNTRY:
                        context.setUserAttribute(CLAIM_SUBJECT_COUNTRY, value);
                        logger.debugf("Set %s to %s", CLAIM_SUBJECT_COUNTRY, value);
                        break;
                    default:
                        context.setUserAttribute(cleanName, value);
                        logger.debugf("Set %s to %s", cleanName, value);
                        break;
                }
            }
        } catch (InvalidNameException e) {
            logger.warnf("Could not parse X.509 Subject Name (NameID): %s. %s", nameId, e.getMessage());
        }
    }

    /**
     * Extracts additional attributes directly from the SAML assertion stored in the
     * context.
     * <p>
     * It filters attributes based on a predefined namespace, standardizes the
     * attribute name by replacing hyphens with underscores, and applies the mapped
     * values to both the brokered context and the user model.
     * </p>
     *
     * @param context The current brokered identity context containing the SAML
     *                assertion.
     */
    private void parseAndMapAssertions(BrokeredIdentityContext context, String flowId, String idpAlias,
            String realmName) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        if (assertion == null || assertion.getAttributeStatements() == null) {
            return;
        }
        for (AttributeStatementType attributeStatement : assertion.getAttributeStatements()) {
            ASTChoiceType dssRequestChoiceType = null;
            for (ASTChoiceType choiceType : attributeStatement.getAttributes()) {
                AttributeType attribute = choiceType.getAttribute();
                String attributeName = attribute.getName();
                if (attributeName == null || attributeName.isBlank() || attribute.getAttributeValue() == null
                        || attribute.getAttributeValue().isEmpty()) {
                    continue;
                }

                if (attribute.getAttributeValue().size() > 1) {
                    // Should never append according to IDP but log it
                    logger.warnf("Found multiple values (%d) in attribute %s",
                            attribute.getAttributeValue().size(), attributeName);
                }

                Object valObj = attribute.getAttributeValue().get(0);
                if (valObj == null) {
                    continue;
                }
                if (!attributeName.startsWith(LUXTRUST_ATTRIBUTE_NAMESPACE)) {
                    continue;
                }
                String cleanName = attributeName.substring(LUXTRUST_ATTRIBUTE_NAMESPACE.length());
                String attributeValue = valObj.toString().trim();

                if (FULL_CERTIFICATE.equals(cleanName)) {
                    extractCertificateDetails(context, attributeValue);
                    continue;
                }

                cleanName = CLAIM_SUBJECT_PREFIX + cleanName.toLowerCase().replace('-', '_');
                if (cleanName.length() > KEYCLOAK_NAME_MAX_LENGTH) {
                    // Name too big to fit in database. Ignore and notify
                    logger.warnf("Ignore assertion %s because name length %d exceeds maximum (%d characters)",
                            attributeName, cleanName.length(), KEYCLOAK_NAME_MAX_LENGTH);
                    continue;
                }

                if ("luxtrust_dssrequest".equals(cleanName)) {
                    dssRequestChoiceType = choiceType;
                    SignatureResult signatureResult = PadesUtils.parseDssResponse(attributeValue);
                    AuthenticationSessionModel authSession = context.getAuthenticationSession();
                    String uploadUrl = authSession.getAuthNote(CONTEXT_DOCUMENT_UPLOAD_PATH);
                    authSession.removeAuthNote(CONTEXT_DOCUMENT_UPLOAD_PATH);
                    String documentServerTimeout = authSession.getAuthNote(DOCUMENT_SERVER_TIMEOUT);
                    authSession.removeAuthNote(DOCUMENT_SERVER_TIMEOUT);
                    Duration serverTimeoutDuration = Duration.ofSeconds(5);
                    if (documentServerTimeout != null && !documentServerTimeout.isBlank()) {
                        try {
                            serverTimeoutDuration = Duration
                                    .ofSeconds(Long.parseLong(documentServerTimeout));
                        } catch (NumberFormatException e) {
                            logger.warnf("Invalid document server timeout: %s. Using default 5 seconds.",
                                    documentServerTimeout);
                        }
                    }

                    String customUserAgent = String.format("%s/%s", realmName, idpAlias);
                    try {
                        logger.debugf("Upload signed document to %s (%s)", uploadUrl,
                                signatureResult.resultMajor());
                        PadesUtils.uploadPdfToClient(uploadUrl, customUserAgent, flowId, serverTimeoutDuration,
                                signatureResult);
                    } catch (Exception e) {
                        logger.errorf("Failed to upload signed document to %s. %s", uploadUrl,
                                e.getMessage());
                        String redirectUri = authSession.getRedirectUri();
                        if (redirectUri != null) {
                            UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri)
                                    .queryParam(OAuth2Constants.ERROR, UPLOAD_DOCUMENT_ERROR);
                            String state = authSession.getClientNote(OAuth2Constants.STATE);
                            if (state != null) {
                                uriBuilder.queryParam(OAuth2Constants.STATE, state);
                            }
                            Response errorResponse = Response.status(Response.Status.FOUND)
                                    .location(uriBuilder.build())
                                    .build();
                            throw new WebApplicationException(errorResponse);
                        }
                        throw new IdentityBrokerException("Unable to upload signed document");
                    }
                    continue;
                }

                if (attributeValue.length() > KEYCLOAK_VALUE_MAX_LENGTH) {
                    // Value too big to fit in database. Ignore and notify
                    logger.warnf("Ignore assertion %s because value length %d exceeds maximum (%d characters)",
                            attributeName, attributeValue.length(), KEYCLOAK_VALUE_MAX_LENGTH);
                    continue;
                }
                logger.debugf("Set %s to %s", cleanName, attributeValue);
                context.setUserAttribute(cleanName, attributeValue);
            }
            if (dssRequestChoiceType != null) {
                attributeStatement.removeAttribute(dssRequestChoiceType);
            }
        }
    }

    private void extractCertificateDetails(BrokeredIdentityContext context, String attributeValue) {
        if (attributeValue == null || attributeValue.isBlank()) {
            return;
        }
        try {
            byte[] certBytes = Base64.getDecoder().decode(attributeValue);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

            // Certificate hash. The full base64 certificate is too large for Keycloak
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            String thumbprint = sb.toString();
            context.setUserAttribute(CLAIM_CERTIFICATE_THUMBPRINT, thumbprint);
            logger.debugf("Set %s to %s", CLAIM_CERTIFICATE_THUMBPRINT, thumbprint);

            // Issuer common name
            String issuerCommonName = Utils.extractX500Attribute(cert.getIssuerX500Principal().getName(), "CN");
            if (issuerCommonName != null) {
                if (issuerCommonName.length() > KEYCLOAK_VALUE_MAX_LENGTH) {
                    // Value too big to fit in database. Ignore and notify
                    logger.warnf("Ignore X.500 attribute %s because value length %d exceeds maximum (%d characters)",
                            CLAIM_CERTIFICATE_ISSUER, issuerCommonName.length(), KEYCLOAK_VALUE_MAX_LENGTH);
                } else {
                    context.setUserAttribute(CLAIM_CERTIFICATE_ISSUER, issuerCommonName);
                    logger.debugf("Set %s to %s", CLAIM_CERTIFICATE_ISSUER, issuerCommonName);
                }
            }

            // Certificate serial number
            String certificateSerialNumber = cert.getSerialNumber().toString(16);
            context.setUserAttribute(CLAIM_CERTIFICATE_SERIAL_NUMBER, certificateSerialNumber);
            logger.debugf("Set %s to %s", CLAIM_CERTIFICATE_SERIAL_NUMBER, certificateSerialNumber);

            // Start validity date
            String certificateNotBefore = cert.getNotBefore().toInstant().toString();
            context.setUserAttribute(CLAIM_CERTIFICATE_NOT_BEFORE, certificateNotBefore);
            logger.debugf("Set %s to %s", CLAIM_CERTIFICATE_NOT_BEFORE, certificateNotBefore);

            // Expiration date
            String certificateNotAfter = cert.getNotAfter().toInstant().toString();
            context.setUserAttribute(CLAIM_CERTIFICATE_NOT_AFTER, certificateNotAfter);
            logger.debugf("Set %s to %s", CLAIM_CERTIFICATE_NOT_AFTER, certificateNotAfter);
        } catch (Exception e) {
            logger.warnf("Unable to parse certificate details: %s", e.getMessage());
        }
    }

}