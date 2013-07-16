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

package ch.SWITCH.aai.idp.x509.principals;

import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;


public class X509OtherName extends AbstractSubjectAltNamePrincipal {

//        DerValue derAltName;
        private final Logger log = LoggerFactory.getLogger(X509OtherName.class);

	public X509OtherName(Object o) {
             super(o);


             ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = null;
             try {
               out = new ObjectOutputStream(bos);   
               out.writeObject(o);
               byte[] yourBytes = bos.toByteArray();
               log.debug ("Subject Alt Byte String {}", yourBytes);
               log.debug ("Subject Alt Object {}", o);
               out.close();
               bos.close();
             } catch (IOException e) {
               log.debug ("Subject Alt ASN String Failed to Decode Bytestream");
             } 
             
	}

        //public String getName() {
        //        return oName.getNameValue();
        //}
        
        /* (non-Javadoc)
         * @see java.lang.Object#toString()
         */
        //public String toString() {
        //        return ASN1Dump.dumpAsString(this);
        //}

}
