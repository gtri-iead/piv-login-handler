/*
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

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.util.URLBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;

public class X509LoginHandler extends AbstractLoginHandler {
    private final Logger log = LoggerFactory.getLogger(X509LoginHandler.class);
    private static final String COOKIE_NAME = "_idp_login_X509_pass-through";

    private static String loginPageURL;
    private static String authenticationServletURL;
    private static String cookieDomain;

    public X509LoginHandler(String loginPageURL,
            String authenticationServletURL,
            String cookieDomain) {
        super();

        setSupportsPassive(false);
        setSupportsForceAuthentication(false);

        X509LoginHandler.loginPageURL = loginPageURL;
        X509LoginHandler.authenticationServletURL = authenticationServletURL;
        X509LoginHandler.cookieDomain = cookieDomain;
    }

    /**
     * Perform login with X509LoginHandler
     *
     * @param  request  HTTPServletRequest
     * @param  response HTTPServletResponse
     */
    public void login(final HttpServletRequest request,
            final HttpServletResponse response) {
        try {
            String redirectURL = null;
            if (isPassThrough(request.getCookies())) {
                log.debug("Cookie '{}' is set: continue with clientauthn protected servlet.", COOKIE_NAME);

                // construct URL for authenticationServlet
                redirectURL = getRedirectURL(request, authenticationServletURL);
            } else {
                // not passThrough
                log.debug("Cookie '{}' is not set: continue with x509 login page.", COOKIE_NAME);
                redirectURL = getRedirectURL(request, loginPageURL);
            }
            // send redirect
            if (! (redirectURL == null)) {
                log.debug("Redirect to {}", redirectURL);
                response.sendRedirect(redirectURL);
            } else {
                log.error("Could not set redirect URL, please check the configuration.");
            }
        } catch (IOException ex) {
            log.error("Unable to redirect to login page or authentication servlet.", ex);
        }

    }

    /**
     * return URL to which redirect will be done
     * depending on the X509 handler configuration,
     * a full URL will be used or a path in the web app
     *
     * @param  request  HTTPServletRequest
     * @return          URL for redirection
     */
    private String getRedirectURL(HttpServletRequest request,
            String url) {
        URLBuilder urlBuilder = null;
        // if URL configured
        if (url.startsWith("http")) {
            urlBuilder = new URLBuilder(url);
        } else {
            // if path configured
            log.debug("No URL configured in loginPageURL: {}", url);

            StringBuilder pathBuilder = new StringBuilder();
            urlBuilder = new URLBuilder();
            urlBuilder.setScheme(request.getScheme());
            urlBuilder.setHost(request.getServerName());
            // set port if not standard port
            if (! (request.getScheme().equals("http")) || (request.getScheme().equals("https"))) {
                urlBuilder.setPort(request.getServerPort());
            }

            pathBuilder.append(request.getContextPath());
            if (!loginPageURL.startsWith("/")) {
                pathBuilder.append("/");
            }
            pathBuilder.append(url);

            urlBuilder.setPath(pathBuilder.toString());
        }
        return urlBuilder.buildURL();
    }

    /**
     * check if pass-through cookie is set
     *
     * @param  cookies  set of cookies from request
     * @return          true or false
     */
    private boolean isPassThrough(Cookie[] cookies) {
        if (cookies == null) {
            return false;
        }
        log.trace("{} Cookie(s) are sent", cookies.length);
        for (int i=0; i<cookies.length; i++) {
            log.trace("Cookie name is {}", cookies[i].getName());
            if (cookies[i].getName().equals(COOKIE_NAME)) {
                return true;
            }
        }
        return false;
    }

    /**
     * set cookie for pass-through
     * cookieDomain can be configured in the handler config
     *
     * @param  path   path to which the client should return the cookie
     */
    public static Cookie createCookie(String path) {
        Cookie cookie = new Cookie(COOKIE_NAME, "1");
        cookie.setMaxAge(60*60*24*365);
        cookie.setPath(path);
        cookie.setSecure(true);
        // use cookieDomain if set
        if (!((cookieDomain == null) || (cookieDomain == ""))) {
            cookie.setDomain(cookieDomain);
        }
        return cookie;
    }
}
