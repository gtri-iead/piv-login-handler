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

import ch.SWITCH.aai.idp.x509.X509LoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

public class X509LoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{

    private String authenticationServletURL;
    private String loginPageURL;
    private String cookieDomain;

    public String getAuthenticationServletURL() {
        return authenticationServletURL;
    }

    public void setAuthenticationServletURL(String url) {
        authenticationServletURL = url;
    }

    public String getLoginPageURL() {
        return loginPageURL;
    }

    public void setLoginPageURL(String url) {
        loginPageURL = url;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public void setCookieDomain(String domain) {
        cookieDomain = domain;
    }

    protected Object createInstance() throws Exception {
        X509LoginHandler handler = new X509LoginHandler(loginPageURL, authenticationServletURL, cookieDomain);

        populateHandler(handler);

        return handler;
    }

    public Class getObjectType() {
        return X509LoginHandler.class;
    }
}
