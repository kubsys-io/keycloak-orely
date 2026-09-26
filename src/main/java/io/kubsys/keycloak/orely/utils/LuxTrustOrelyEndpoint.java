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

import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.validators.DestinationValidator;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Custom SAML endpoint for processing LuxTrust Identity Provider responses.
 * <p>
 * This endpoint extends the standard Keycloak SAML processing to dynamically
 * extract specific LuxTrust attributes from the SAML assertion and inject them
 * into the current authentication session notes.
 * </p>
 */
public final class LuxTrustOrelyEndpoint extends SAMLEndpoint implements Constants {

    public LuxTrustOrelyEndpoint(KeycloakSession session,
            SAMLIdentityProvider provider,
            SAMLIdentityProviderConfig config,
            UserAuthenticationIdentityProvider.AuthenticationCallback callback,
            DestinationValidator destinationValidator) {
        super(session, provider, config, callback, destinationValidator);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Override
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
            @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
            @FormParam(GeneralConstants.SAML_ARTIFACT_KEY) String samlArt,
            @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new OrelyPostBinding().execute(samlRequest, samlResponse, samlArt, relayState, null);
    }

    @GET
    @Override
    public Response redirectBinding(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
            @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
            @QueryParam(GeneralConstants.SAML_ARTIFACT_KEY) String samlArt,
            @QueryParam(GeneralConstants.RELAY_STATE) String relayState) {
        return Response.status(Response.Status.METHOD_NOT_ALLOWED)
                .entity("SAML Redirect Binding is disabled. Please use HTTP-POST Binding.")
                .type(MediaType.TEXT_PLAIN_TYPE)
                .build();
    }

    @Path("clients/{client_id}")
    @GET
    @Override
    public Response redirectBindingIdpInitiated(@QueryParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
            @QueryParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
            @QueryParam(GeneralConstants.RELAY_STATE) String relayState,
            @PathParam("client_id") String clientId) {
        return Response.status(Response.Status.METHOD_NOT_ALLOWED)
                .entity("SAML Redirect Binding is disabled. Please use HTTP-POST Binding.")
                .type(MediaType.TEXT_PLAIN_TYPE)
                .build();
    }

    /**
     * Extends the default HTTP POST binding to intercept the login response
     * and process extra LuxTrust SAML attributes.
     */
    protected class OrelyPostBinding extends PostBinding {
        @Override
        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder,
                ResponseType responseType, String relayState, String clientId) {
            return super.handleLoginResponse(samlResponse, holder, responseType, relayState, clientId);
        }
    }

}