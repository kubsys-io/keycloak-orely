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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * Utility class providing helper methods for the Orely signature integration.
 * Includes methods for certificate normalization and OASIS DSS XML request
 * generation.
 */
public class Utils implements ErrorCodes, Constants {

	// Principal attributes
	private static final Set<String> PRINCIPAL_ATTRIBUTES = Set.of("CN", "O", "OU", "L", "C");

	/**
	 * Normalizes a PEM-encoded X.509 certificate by removing the standard header,
	 * footer, and all whitespace/newline characters.
	 */
	public static String normalizeCertificate(String rawCert) {
		if (rawCert == null || rawCert.isBlank()) {
			return rawCert;
		}
		return rawCert
				.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "")
				.replaceAll("\\s+", "");
	}

	/**
	 * Masks an email address while leaving it partially identifiable.
	 * <p>
	 * Masking rules:
	 * <ul>
	 * <li>Local part: Retains the first and last characters if length is > 2 (e.g.,
	 * "j***e").</li>
	 * <li>Domain part: Retains the first character and the full Top Level Domain
	 * (e.g., "e***.com").</li>
	 * <li>Invalid input: Returns a generic "***@***.***" if the email is null,
	 * blank, or malformed.</li>
	 * </ul>
	 *
	 * @param email the email address to mask
	 * @return the obfuscated email string
	 */
	public static String maskEmail(String email) {
		if (email == null || email.isBlank() || !email.contains("@")) {
			return "***@***.***";
		}

		String[] parts = email.split("@", 2);
		String localPart = parts[0];
		String domainPart = parts[1];

		// Mask local part
		String maskedLocal = "***";
		if (localPart.length() == 1) {
			maskedLocal = localPart.charAt(0) + "***";
		} else if (localPart.length() == 2) {
			maskedLocal = localPart.charAt(0) + "***";
		} else if (localPart.length() > 2) {
			maskedLocal = localPart.charAt(0) + "***" + localPart.charAt(localPart.length() - 1);
		}

		// Mask domain
		String maskedDomain = "***.***";
		int lastDotIndex = domainPart.lastIndexOf('.');

		if (lastDotIndex > 0) {
			String domainName = domainPart.substring(0, lastDotIndex);
			String tld = domainPart.substring(lastDotIndex); // Includes the dot, e.g., ".com"

			if (domainName.length() >= 1) {
				maskedDomain = domainName.charAt(0) + "***" + tld;
			} else {
				maskedDomain = "***" + tld;
			}
		} else if (domainPart.length() > 0) {
			maskedDomain = domainPart.charAt(0) + "***";
		}

		return maskedLocal + "@" + maskedDomain;
	}

	/**
	 * Masks a personal name by retaining only the first character.
	 * <p>
	 * Example: "John" becomes "J***". If the input is null or blank, it returns
	 * "***".
	 *
	 * @param name the raw name string to mask
	 * @return the masked name
	 */
	public static String maskName(String name) {
		if (name == null || name.isBlank()) {
			return "***";
		}

		String cleanName = name.trim();
		return cleanName.charAt(0) + "***";
	}

	/**
	 * Masks a subject serial number (such as a national ID or certificate
	 * serial).
	 * <p>
	 * Masking rules based on length:
	 * <ul>
	 * <li>4 characters or fewer: Returned entirely unmasked.</li>
	 * <li>Between 5 and 8 characters: Retains the first 4 characters and masks the
	 * rest.</li>
	 * <li>More than 8 characters: Retains the first 4 and the last 4 characters,
	 * masking the middle.</li>
	 * </ul>
	 *
	 * @param subjectSerialNumber the serial number string to mask
	 * @return the partially masked serial number, or the original string if it is
	 *         null or blank
	 */
	public static String maskSubjectSerialNumber(String subjectSerialNumber) {
		if (subjectSerialNumber == null || subjectSerialNumber.isBlank()) {
			return subjectSerialNumber;
		}

		String clean = subjectSerialNumber.trim();
		int length = clean.length();
		if (length <= 4) {
			return clean;
		}

		if (length <= 8) {
			return clean.substring(0, 4) + "*".repeat(length - 4);
		}

		return clean.substring(0, 4)
				+ "*".repeat(length - 8)
				+ clean.substring(length - 4);
	}

	public static X509Certificate getCertificate(String cleanCert)
			throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		byte[] decodedBytes = Base64.getDecoder().decode(cleanCert);
		Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(decodedBytes));
		return (X509Certificate) certificate;
	}

	/**
	 * Filters an X.500 Principal to retain only the allowed attributes.
	 * <p>
	 * This securely parses the Distinguished Name (DN) and removes unwanted
	 * attributes
	 * (such as OIDs like 1.2.840.113549.1.9.1 or email addresses), keeping only
	 * the standard attributes defined in the allowlist (CN, O, OU, L, C).
	 * </p>
	 * 
	 * @param principal The X500Principal extracted from the certificate.
	 * @return The sanitized string representation of the Principal, or null if the
	 *         input is null.
	 * @throws IllegalArgumentException If the Principal's name cannot be parsed.
	 */
	public static String sanitize(X500Principal principal) {
		if (principal == null) {
			return null;
		}

		try {
			LdapName ldapName = new LdapName(principal.getName());

			List<Rdn> filteredRdns = ldapName.getRdns().stream()
					.filter(rdn -> PRINCIPAL_ATTRIBUTES.contains(rdn.getType().toUpperCase()))
					.collect(Collectors.toList());

			return new LdapName(filteredRdns).toString();

		} catch (InvalidNameException e) {
			throw new IllegalArgumentException("Invalid Principal format: " + principal.getName(), e);
		}
	}

	public static String extractX500Attribute(String x500Name, String attributeName) {
		try {
			LdapName ldapName = new LdapName(x500Name);
			for (Rdn rdn : ldapName.getRdns()) {
				if (attributeName.equalsIgnoreCase(rdn.getType())) {
					return String.valueOf(rdn.getValue()).trim();
				}
			}
		} catch (InvalidNameException e) {
			throw new IllegalArgumentException("Invalid Principal format: " + x500Name, e);
		}
		return null;
	}

	/**
	 * Merges two X.500 Distinguished Names (DN).
	 * Attributes from the principal will replace those in the base if they exist,
	 * or will be appended if they are not present in the base DN.
	 *
	 * @param x500base      The base X.500 DN string (e.g., "CN=John, O=Company,
	 *                      C=US").
	 * @param x500principal The X.500 DN string containing attributes to merge or
	 *                      add.
	 * @return A new merged X.500 DN string.
	 * @throws InvalidNameException If either input string is not a valid LDAP/X.500
	 *                              DN format.
	 */
	public static String mergePrincipals(String x500base, String x500principal) throws InvalidNameException {
		if (x500base == null || x500base.isBlank()) {
			return x500principal;
		}
		if (x500principal == null || x500principal.isBlank()) {
			return x500base;
		}

		LdapName baseName = new LdapName(x500base);
		LdapName mergeName = new LdapName(x500principal);

		List<Rdn> baseRdns = new ArrayList<>(baseName.getRdns());
		List<Rdn> mergeRdns = mergeName.getRdns();

		for (Rdn mergeRdn : mergeRdns) {
			String typeToMerge = mergeRdn.getType();
			boolean replaced = false;

			for (int i = 0; i < baseRdns.size(); i++) {
				if (baseRdns.get(i).getType().equalsIgnoreCase(typeToMerge)) {
					baseRdns.set(i, mergeRdn);
					replaced = true;
					break;
				}
			}

			if (!replaced) {
				baseRdns.add(mergeRdn);
			}
		}

		return new LdapName(baseRdns).toString();
	}
}