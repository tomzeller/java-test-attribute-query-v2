/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test;

import java.io.File;
import java.net.Socket;
import java.security.KeyException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.RandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.util.XMLHelper;

/**
 * Send an attribute query to an IdP.
 * 
 * @see <a href="https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaSOAPClientExample">OSTwoUserManJavaSOAPClientExample</a>
 */
public final class SAMLAttributeQueryExample {

    /** Constructor. */
    private SAMLAttributeQueryExample() {
    }

    /**
     * Send an attribute query to an IdP.
     * 
     * @param args program arguments
     */
    public static void main(String[] args) {

        String serverEndpoint = "https://idp.example.org:8443/idp/profile/SAML2/SOAP/AttributeQuery";

        String clientTLSPrivateKeyFile = "/opt/local/etc/shibboleth/sp-key.pem";
        String clientTLSCertificateFile = "/opt/local/etc/shibboleth/sp-cert.pem";

        String requester = "https://sp.example.org/shibboleth";

        String principalName = "jdoe";
        String expectedAttributeFriendlyName = "mail";
        String expectedAttributeValue = "jdoe@example.org";

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        // Build the outgoing message structures
        AttributeQuery attributeQuery = buildAttributeQuery(requester, principalName);

        Envelope envelope = buildSOAP11Envelope(attributeQuery);

        // SOAP context used by the SOAP client
        BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
        soapContext.setOutboundMessage(envelope);

        // This part is for client TLS support
        X509Credential clientTLSCred = getClientTLSCred(clientTLSPrivateKeyFile, clientTLSCertificateFile);
        StaticClientKeyManager keyManager =
                new StaticClientKeyManager(clientTLSCred.getPrivateKey(), clientTLSCred.getEntityCertificate());

        // Build the SOAP client
        HttpClientBuilder clientBuilder = new HttpClientBuilder();
        clientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(keyManager,
                new DelegateToApplicationX509TrustManager()));

        HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), parserPool);

        // Send the message
        try {
            soapClient.send(serverEndpoint, soapContext);
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (SecurityException e) {
            e.printStackTrace();
        }

        // Access the SOAP response envelope
        Envelope soapResponse = (Envelope) soapContext.getInboundMessage();

        System.out.println("SOAP Response was:");
        System.out.println(XMLHelper.prettyPrintXML(soapResponse.getDOM()));

        // Verify the response was a success and the expected attribute was returned.
        if (verifyResponse(soapResponse, principalName, expectedAttributeFriendlyName, expectedAttributeValue)) {
            System.out.println("Response completed successfully.");
        } else {
            System.err.println("Response not completed successfully.");
        }

    }

    /**
     * Build the envelope.
     * 
     * @param payload the payload
     * @return the envelope
     */
    private static Envelope buildSOAP11Envelope(XMLObject payload) {
        XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
        Envelope envelope =
                (Envelope) bf.getBuilder(Envelope.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        Body body = (Body) bf.getBuilder(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);

        body.getUnknownXMLObjects().add(payload);
        envelope.setBody(body);

        return envelope;
    }

    /**
     * Builds a basic attribute query.
     * 
     * @param requester the requester
     * @param principal the principal
     * 
     * @return basic attribute query
     */
    protected static AttributeQuery buildAttributeQuery(String requester, String principal) {
        XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
        SAMLObjectBuilder<Issuer> issuerBuilder =
                (SAMLObjectBuilder<Issuer>) bf.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requester);

        SAMLObjectBuilder<NameID> nameIdBuilder =
                (SAMLObjectBuilder<NameID>) bf.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(principal);
        nameId.setFormat(NameID.PERSISTENT);

        SAMLObjectBuilder<Subject> subjectBuilder =
                (SAMLObjectBuilder<Subject>) bf.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        SAMLObjectBuilder<AttributeQuery> attributeQueryBuilder =
                (SAMLObjectBuilder<AttributeQuery>) bf.getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
        AttributeQuery query = attributeQueryBuilder.buildObject();
        query.setID(new RandomIdentifierGenerator().generateIdentifier());
        query.setIssueInstant(new DateTime());
        query.setIssuer(issuer);
        query.setSubject(subject);
        query.setVersion(SAMLVersion.VERSION_20);

        return query;
    }

    /* --------------------------------------------------------- */

    /**
     * Get client credential.
     * 
     * @param clientTLSPrivateKeyFile path to private key file
     * @param clientTLSCertificateFile path to certificate file
     * @return the credential
     */
    private static X509Credential getClientTLSCred(String clientTLSPrivateKeyFile, String clientTLSCertificateFile) {
        PrivateKey privateKey = null;
        X509Certificate cert = null;

        try {
            privateKey = SecurityHelper.decodePrivateKey(new File(clientTLSPrivateKeyFile), null);
            cert = X509Util.decodeCertificate(new File(clientTLSCertificateFile)).iterator().next();
        } catch (KeyException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return SecurityHelper.getSimpleCredential(cert, privateKey);
    }

    /**
     * Verify that response was a success and the expected attribute was returned.
     * 
     * @param soapResponse the response
     * @param principal the principal
     * @param expectedAttributeFriendlyName the expected attribute name
     * @param expectedAttributeValue the expected attribute value
     * @return whether or not the response was a success and the expected attribute was returned
     */
    public static boolean verifyResponse(Envelope soapResponse, String principal, String expectedAttributeFriendlyName,
            String expectedAttributeValue) {
        //
        Response response = (Response) soapResponse.getBody().getUnknownXMLObjects().get(0);
        if (!response.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
            System.err.println("Response was not a success.");
            return false;
        }

        Assertion assertion = response.getAssertions().get(0);

        if (!assertion.getSubject().getNameID().getValue().equals(principal)) {
            System.err.println("Subject does not match.");
            return false;
        }

        boolean expectedAttributeWasReturned = false;
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                for (XMLObject value : attribute.getAttributeValues()) {
                    if (attribute.getFriendlyName().equals(expectedAttributeFriendlyName)) {
                        if (((XSString) value).getValue().equals(expectedAttributeValue)) {
                            expectedAttributeWasReturned = true;
                        }
                    }
                }
            }
        }

        if (!expectedAttributeWasReturned) {
            System.err.println("Response did not contain the expected attribute.");
            return false;
        }

        return true;
    }

}

/**
 * Static client key manager.
 */
class StaticClientKeyManager implements X509KeyManager {

    /** Client alias. */
    private final String clientAlias = "myStaticAlias";

    /** Private key. */
    private PrivateKey privateKey;

    /** Certificate. */
    private X509Certificate cert;

    /**
     * Constructor.
     * 
     * @param newPrivateKey the private key
     * @param newCert the certificate
     */
    public StaticClientKeyManager(PrivateKey newPrivateKey, X509Certificate newCert) {
        privateKey = newPrivateKey;
        cert = newCert;
    }

    /** {@inheritDoc} */
    public String chooseClientAlias(String[] as, Principal[] aprincipal, Socket socket) {
        return clientAlias;
    }

    /** {@inheritDoc} */
    public String chooseServerAlias(String s, Principal[] aprincipal, Socket socket) {
        return null;
    }

    /** {@inheritDoc} */
    public X509Certificate[] getCertificateChain(String s) {
        return new X509Certificate[] {cert};
    }

    /** {@inheritDoc} */
    public String[] getClientAliases(String s, Principal[] aprincipal) {
        return new String[] {clientAlias};
    }

    /** {@inheritDoc} */
    public PrivateKey getPrivateKey(String s) {
        return privateKey;
    }

    /** {@inheritDoc} */
    public String[] getServerAliases(String s, Principal[] aprincipal) {
        return null;
    }

}

/** A {@link X509TrustManager}s that delegates validation of X.509 certificates to the application. */
class DelegateToApplicationX509TrustManager implements X509TrustManager {

    /** {@inheritDoc} */
    public void checkClientTrusted(X509Certificate[] certs, String auth) {
    }

    /** {@inheritDoc} */
    public void checkServerTrusted(X509Certificate[] certs, String auth) {
    }

    /** {@inheritDoc} */
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[] {};
    }
}
