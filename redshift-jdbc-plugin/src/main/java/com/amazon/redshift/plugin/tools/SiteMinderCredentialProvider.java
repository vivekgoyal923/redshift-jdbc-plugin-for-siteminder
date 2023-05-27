// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.redshift.plugin.tools;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import com.amazon.redshift.plugin.SamlCredentialsProvider;
import com.amazonaws.SdkClientException;
import com.amazonaws.util.IOUtils;
import com.amazonaws.util.StringUtils;

import org.apache.commons.codec.binary.Base64;
/**
 *<p>
 * This is the main plugin class.
 *</p>
 *
 * @author Dipankar Ghosal , Amazon Web Services, Inc.
 *
 */
public class SiteMinderCredentialProvider extends SamlCredentialsProvider {
    /**
     * Here we are defining a new connection property key called "sso_url". This property
     * will be specific to the SiteMinderSamlCredentialsProvider and will be used to provide SSO URL
     * information through the connection string.
     * <p>
     * This means that a user wanting to use this credential provider may include the following in
     * the connection string:
     * <p>
     * <code>
     *          jdbc:redshift:iam://[host]:[port]/[database]?sso_url=[value]
     * </code>
     *
     *
     */

	private static final String SSO_URL = "sso_url";

	protected String m_sso_url;

	@Override
	public void addParameter(String key, String value) {
		super.addParameter(key, value);

		if (SSO_URL.equalsIgnoreCase(key)) {
			m_sso_url = value;
		}
	}

	@Override
	protected String getSamlAssertion() throws IOException {

		if (StringUtils.isNullOrEmpty(m_sso_url)) {
			/*throw new IOException("Missing required property: " + SSO_URL);*/
			m_sso_url = "https://sqauthprod.sq.com.sg/affwebservices/public/saml2sso?SPID=aws_redshift";
		}

		CloseableHttpClient httpClient = null;

		try {

			URLConnection con = new URL(m_sso_url).openConnection();
			con.connect();
			@SuppressWarnings("unused")
			InputStream is = con.getInputStream();
			String redirected_url = con.getURL().toString();
			httpClient = buildHttpClient();
			return handleSamlAssertion(httpClient, redirected_url);
		} catch (Exception e) {
			throw new SdkClientException("Failed to create SSLContext.", e);
		} finally {
			IOUtils.closeQuietly(httpClient, null);
		}
	}

	/**
	 * Retrieves SAML assertion from Siteminder containing AWS roles.
	 */
	private String handleSamlAssertion(CloseableHttpClient httpClient, String redirected_url) throws IOException {
		/**
		 * redirected_url = "https://sqauthprod.sq.com.sg/affwebservices/public/processlogin.jsp";
		 * postParameters.add(new BasicNameValuePair("smagentname", "-SM-msHB16AuMFTmVp7S2jp6QFaszkILA8Q3b9dM72eLovIIMJvBKnBoK%2BrZBJYdxpWXBMEVCR%2BI9fk51zV3Ky1u6%2F5nVjw2kDOz"));
		 * postParameters.add(new BasicNameValuePair("target", "-SM-HTTPS%3A%2F%2Fsqauthprod.sq.com.sg%2Faffwebservices%2Fredirectjsp%2Fredirect.jsp%3FSPID%3Durn%3Aamazon%3Awebservices%26SMPORTALURL%3Dhttps-%3A-%2F-%2Fsqauthprod.sq.com.sg-%2Faffwebservices-%2Fpublic-%2Fsaml2sso%26SAMLTRANSACTIONID%3D12044e54--607f3d1b--08ff66c9--c4344667--11cecfaf--3b59"));
		 */
		redirected_url = redirected_url.replace("dologin","processlogin");
		redirected_url = redirected_url.replace("SMAGENTNAME","smagentname");
		redirected_url = redirected_url.replace("TARGET","target");
		HttpPost httpost = new HttpPost(redirected_url);
		String body = null;
		ArrayList<NameValuePair> postParameters;
		postParameters = new ArrayList<NameValuePair>();
		postParameters.add(new BasicNameValuePair("USER", m_userName));
		postParameters.add(new BasicNameValuePair("PASSWORD", m_password));
		postParameters.add(new BasicNameValuePair("SMENC", "ISO-8859-1"));
		
		httpost.setEntity(new UrlEncodedFormEntity(postParameters, "UTF-8"));
		String response = null;
		try {
			CloseableHttpResponse responseSAML = httpClient.execute(httpost);

			int requestStatus = responseSAML.getStatusLine().getStatusCode();
			if (requestStatus != 200) {
				throw new RuntimeException("Failed : HTTP error code : " + responseSAML.getStatusLine().getStatusCode()
						+ " : Reason : " + responseSAML.getStatusLine().getReasonPhrase());
			}

			body = EntityUtils.toString(responseSAML.getEntity());
			response = getSAMlresponse(body);
		} catch (Exception e) {
			throw new SdkClientException("No response from url.", e);
		}

		if (null != response) {

			/*response = updateDbGroups(response);*/
			return response.replace("&#x2b;", "+").replace("&#x3d;", "=");

		} else {
			String string = String.format("Failed to retrieve SAMLAssertion, %s %s",  redirected_url, body);
			throw new IOException(string);
		}

	}

	/**
	 * Utility method to get the SANMLResponse from the hidden input. Used this as
	 * the getInputTagsfromHTML was not responding/executing.
	 *
	 * @param response
	 * @return
	 */
	private String getSAMlresponse(String response) {

		int indexStr = 0;
		String hiddenString = "input type=\"hidden\"";
		String value = "";
		String name = "";
		while (true) {
			indexStr = response.indexOf(hiddenString, indexStr) + hiddenString.length();
			if (indexStr > hiddenString.length()) {
				int start = response.indexOf("value=\"", indexStr) + 7;
				int end = response.indexOf("\"", start);
				value = response.substring(start, end);

				start = response.indexOf("name=\"", indexStr) + 6;
				end = response.indexOf("\"", start);
				name = response.substring(start, end);
				indexStr = end;

			} else {
				break;
			}
		}
		return (name.equalsIgnoreCase("SAMLResponse") ? value : null);
	}

	/**
	 * Creating the instance of the httpclient to restrict/enable redirect
	 *
	 *
	 * @return
	 */
	private static CloseableHttpClient buildHttpClient() {
		CloseableHttpClient httpclient = HttpClients.custom().setRedirectStrategy(new LaxRedirectStrategy()).build();
		return httpclient;
	}

	/**
	 * Utility method to get the SANMLResponse from the hidden input. Used this as
	 * the getInputTagsfromHTML was not responding/executing.
	 *
	 * @param samlassertion
	 * @return processed_response
	 */
	private String updateDbGroups(String samlassertion) {

		byte[] arrayOfByte = Base64.decodeBase64(samlassertion);
		String to_process = new String(arrayOfByte, StandardCharsets.UTF_8);

		String string_1 = String.format("Before Processing \n SAMLAssertion: %s \n Decoded: %s",  samlassertion, to_process);
		System.out.print(string_1);
		
		to_process = to_process.replaceAll("CN=", "");
		to_process = to_process.replaceAll("DC=", "");
		to_process = to_process.replaceAll("OU=", "");

		byte[] processed_assertion = Base64.encodeBase64(to_process.getBytes());
		
		byte[] arrayOfByteProcessed = Base64.decodeBase64(processed_assertion);
		String processed = new String(arrayOfByteProcessed, StandardCharsets.UTF_8);

		String string_2 = String.format("Processed \n SAMLAssertion: %s \n Decoded: %s",  new String(processed_assertion), processed);
		System.out.print(string_2);

		String string_3 = new String(string_1+"\n"+string_2);

		return  string_3;
	}

}
