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

public interface ErrorCodes {
	String GENERIC_ERROR = "PTEC_001";
	String BAD_CONTEXT_SYNTAX = "PTEC_100";
	String ADD_ENV_ATTRIBUTES_ERROR = "PTEC_101";
	String ADD_EXTENSIONS_ERROR = "PTEC_102";
	String REQUESTED_ATTRIBUTE_UNNAMED = "PTEC_103";
	String BUILD_DOCUMENT_ERROR = "PTEC_104";
	String AUTHN_BUILD_ERROR = "PTEC_105";

	String MISSING_SIGNATURE_CONTEXT = "PTEC_200";
	String MISSING_DOCUMENT_DOWNLOAD_PATH = "PTEC_201";
	String BAD_DOCUMENT_DOWNLOAD_PATH = "PTEC_202";
	String MISSING_DOCUMENT_UPLOAD_PATH = "PTEC_203";
	String BAD_DOCUMENT_UPLOAD_PATH = "PTEC_204";
	String DOWNLOAD_DOCUMENT_ERROR = "PTEC_205";
	String SIGNATURE_PLACEMENT_MISSING = "PTEC_206";
	String DOWNLOAD_DOCUMENT_INTERRUPTED = "PTEC_207";
	String DOCUMENT_SIGNATURE_ERROR = "PTEC_208";
	String SIGN_REQUEST_BUILDER_ERROR = "PTEC_209";
	String UPLOAD_DOCUMENT_ERROR = "PTEC_210";
	String DOWNLOAD_WATERMARK_ERROR = "PTEC_211";
	String PARTIAL_SIGNATURE_POSITION = "PTEC_212";
	String BAD_PLACEMENT_COORDINATES = "PTEC_213";
}
