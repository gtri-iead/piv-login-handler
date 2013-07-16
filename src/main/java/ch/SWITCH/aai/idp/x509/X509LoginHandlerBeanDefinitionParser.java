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
import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;

public class X509LoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(X509NamespaceHandler.NAMESPACE, "X509");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return X509LoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        builder.addPropertyValue("authenticationServletURL", DatatypeHelper.safeTrim(config.getAttributeNS(null, "authenticationServletURL")));
        builder.addPropertyValue("loginPageURL", DatatypeHelper.safeTrim(config.getAttributeNS(null, "loginPageURL")));
        builder.addPropertyValue("cookieDomain", DatatypeHelper.safeTrim(config.getAttributeNS(null, "cookieDomain")));
    }
}
