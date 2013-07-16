/*
 * Copyright 2013 GTRI
 * Copyright [2012] [SWITCH]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.SWITCH.aai.idp.x509;

import java.security.Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.SWITCH.aai.idp.x509.principals.DNSNamePrincipal;
import ch.SWITCH.aai.idp.x509.principals.EMailPrincipal;
import ch.SWITCH.aai.idp.x509.principals.URIPrincipal;
import ch.SWITCH.aai.idp.x509.principals.X509OtherName;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.gtri.gfipm.bae.v2_0.FASCNSubjectIdentifier;
import org.gtri.gfipm.bae.v2_0.PIVUUIDSubjectIdentifier;
import org.gtri.gfipm.bae.v2_0.InvalidFASCNException;


public class X509LoginServlet extends HttpServlet {

    private static final long serialVersionUID = -4431927396568561930L;
    private final Logger log = LoggerFactory.getLogger(X509LoginServlet.class);
    private static final String GETPAR_PASSTHROUGH = "x509-pass-through";
    public void init() {
        log.trace("servlet initialization");
    }

    protected void service(HttpServletRequest request, HttpServletResponse response) {
        log.trace("servlet service");

        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        log.debug("{} X509Certificates found in request", certs.length);

        if (certs.length < 1) {
            log.error("No X509Certificates found in request");
            request.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, "No X509Certificates found in request");
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
        }

        // Take only the end entity certificate
        X509Certificate cert = certs[0];
        
        
        Subject subject = new Subject();
        Set<Principal> principals = subject.getPrincipals();
        
        // Add the cert to the public credentials of the subject
        Set<Object> publicCredentials = subject.getPublicCredentials();
        publicCredentials.add(cert);
        
        log.debug("Adding SubjectX500Principal {} of type {} as principal to subject", cert.getSubjectX500Principal(), X500Principal.class);
//        principals.add(cert.getSubjectX500Principal());
               
        try {
            if (FASCNSubjectIdentifier.hasFASCN (cert)) {
                log.debug("Found FASCN in cert");

                FASCNSubjectIdentifier fascnId = new FASCNSubjectIdentifier (cert);
                log.debug("Created FASCN Subject Identifier: {}", fascnId);

                principals.add (new URIPrincipal(fascnId));
                log.debug("Added URI Principal based on FASCN: {}", fascnId);
            }

            if (PIVUUIDSubjectIdentifier.hasPIVIUUID(cert)) {
               log.debug("Found UUID in cert");
               
               PIVUUIDSubjectIdentifier uuidId = new PIVUUIDSubjectIdentifier (cert);
               log.debug ("Created UUID Subject Identifier: {}", uuidId);

               principals.add (new URIPrincipal(uuidId));
               log.debug("Added URI Principal based on FASCN: {}", uuidId);
            }

          } catch (InvalidFASCNException e) {
		log.error("Invalid FASCN Exception while parsing certificate {}", cert, e);
          } catch (CertificateParsingException e) {
                log.error("Certificate parsing Exception while parsing certificate {}", cert, e);
	  } catch (java.io.IOException e) {
                log.error("Error parsing subject alt field {}", cert, e);
          }

        log.debug("Forward subject {} to the AuthenticationEngine", subject); 
        request.setAttribute(LoginHandler.SUBJECT_KEY, subject);
        
        log.debug("GET parameter {} is {}", GETPAR_PASSTHROUGH, request.getParameter(GETPAR_PASSTHROUGH));
        if (request.getParameter(GETPAR_PASSTHROUGH) != null) {
            Cookie cookie = X509LoginHandler.createCookie(request.getContextPath());
            log.trace("Set Cookie {}", cookie);
            response.addCookie(cookie);
        }

        this.log.trace("Set request attribute {} to {}", LoginHandler.AUTHENTICATION_METHOD_KEY, AuthnContext.X509_AUTHN_CTX);
        request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, AuthnContext.X509_AUTHN_CTX);
        AuthenticationEngine.returnToAuthenticationEngine(request, response);
    }

}
