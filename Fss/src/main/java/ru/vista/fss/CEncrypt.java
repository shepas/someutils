package ru.vista.fss;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import ru.CryptoPro.JCPxml.Consts;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

class CEncrypt {
    private X509Certificate fssCertificate;
    private SecretKey sessionKey;
    PrivateKey moPrivateKey;
    X509Certificate moCertificate;
    private EncryptedKey encryptedKey;
    boolean passwordIsValid;


    CEncrypt(Document doc, String fssCert, String alias, String password) throws Exception {
        fssCertificate = loadFssCertificate(fssCert);
        sessionKey =  KeyGenerator.getInstance("GOST28147").generateKey();
        loadMOCertificate(alias, password);
        encryptedKey = wrapKey(doc, sessionKey, fssCertificate);
    }

    CEncrypt(String alias, String password) throws Exception {
        passwordIsValid = loadMOCertificate(alias, password);
    }


    //Загрузка сертификата МО
    private boolean loadMOCertificate(String alias, String password) throws Exception {
        try {
            KeyStore ks = KeyStore.getInstance("HDImageStore");
            ks.load(null, null);
            moPrivateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
            moCertificate = (X509Certificate) ks.getCertificate(alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //Загрузка сертификата ФСС
    private X509Certificate loadFssCertificate(String fileName) throws Exception {
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(fileName));
        return (X509Certificate) certificate;
    }

    //Шифрование сессионого ключа
    private EncryptedKey wrapKey(Document doc, SecretKey sessionKey, X509Certificate cert) throws Exception {
        XMLCipher keyCipher = XMLCipher.getInstance(Consts.URI_GOST_TRANSPORT);
        keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());
        KeyInfo certKeyInfo = new KeyInfo(doc);
        org.apache.xml.security.keys.content.X509Data x509data = new org.apache.xml.security.keys.content.X509Data(doc);
        x509data.addCertificate(moCertificate);
        certKeyInfo.add(x509data);
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, sessionKey);
        encryptedKey.setKeyInfo(certKeyInfo);
        return encryptedKey;
    }

    //Шифрование документа
    Document encrypt(Document doc) throws Exception {
        Element element = doc.getDocumentElement();
        XMLCipher xmlCipher = XMLCipher.getInstance(Consts.URI_GOST_CIPHER);
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        KeyInfo keyInfo = new KeyInfo(doc);
        keyInfo.add(encryptedKey);
        encryptedData.setKeyInfo(keyInfo);
        xmlCipher.doFinal(doc, element, false);
        return doc;
    }

    //
    Document prepareDoc(Document doc) throws Exception{
        Element header = (Element) doc.getElementsByTagName("S:Header").item(0);
        //Добавление тега Security
        Element security = doc.createElement("wsse:Security");
        security.setAttribute("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        security.setAttribute("S:Actor", "http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn);
        //Добавление тега wsse:BinarySecurityToken
        Element binarySecToken = doc.createElement("wsse:BinarySecurityToken");
        binarySecToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        binarySecToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        BASE64Encoder encoder = new BASE64Encoder();
        binarySecToken.setTextContent(encoder.encodeBuffer(moCertificate.getEncoded()).replace("\r", ""));
        security.appendChild(binarySecToken);
        header.appendChild(security);
        return doc;
    }

    //Подпись документа
    Document signDoc(Document doc) throws Exception {
        JCPXMLDSigInit.init();
        String strDoc = Utils.dom2String(doc);
        doc = Utils.loadXMLFromString(strDoc);
        Element body = (Element) doc.getElementsByTagName("soapenv:Body").item(0);
        body.setIdAttribute("wsu:Id", true);
        final XMLSignature sig = new XMLSignature(doc, "", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element anElement = null;
        for (int i = 0; i < doc.getElementsByTagName("wsse:Security").getLength(); i++){
            Element element = (Element) doc.getElementsByTagName("wsse:Security").item(i);
            if (element.getAttribute("S:actor").contains("http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn)){
                anElement = element;
            }
        }
        anElement.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        sig.addDocument("#OGRN_" + StaticsVariables.moOgrn, transforms, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        sig.getKeyInfo();
        Element keyInfo = (Element) sig.getElement().getElementsByTagName("ds:KeyInfo").item(0);
        Element securityTokenRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn);
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenRef.appendChild(reference);
        keyInfo.appendChild(securityTokenRef);
        sig.sign(moPrivateKey);
        Element sigValue = (Element) doc.getElementsByTagName("ds:SignatureValue").item(0);
        sigValue.setTextContent(sigValue.getTextContent().replace("\n", ""));
        return doc;
    }

    //Лютая дичь при возможности объединить в 1 метод
    //Подпись документа врачем
    Document signDocByDoc(Document doc, String eln, String num) throws Exception {
        JCPXMLDSigInit.init();
        String strDoc = Utils.dom2String(doc);
        doc = Utils.loadXMLFromString(strDoc);
        Element body = (Element) doc.getElementsByTagName("TREAT_PERIOD").item(doc.getElementsByTagName("TREAT_PERIOD").getLength() - 1);
        body.setIdAttribute("wsu:Id", true);
        final XMLSignature sig = new XMLSignature(doc, "", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element anElement = null;
        for (int i = 0; i < doc.getElementsByTagName("wsse:Security").getLength(); i++){
            Element element = (Element) doc.getElementsByTagName("wsse:Security").item(i);
            if (element.getAttribute("S:actor").contains("http://eln.fss.ru/actor/doc/" + eln + "_" + num + "_doc")){
                anElement = element;
            }
        }
        anElement.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        sig.addDocument("#ELN_" + eln + "_" + num + "_doc", transforms, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        sig.getKeyInfo();
        Element keyInfo = (Element) sig.getElement().getElementsByTagName("ds:KeyInfo").item(0);
        Element securityTokenRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/doc/" + eln + "_" + num + "_doc");
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenRef.appendChild(reference);
        keyInfo.appendChild(securityTokenRef);
        sig.sign(moPrivateKey);
        Element sigValue = (Element) doc.getElementsByTagName("ds:SignatureValue").item(0);
        sigValue.setTextContent(sigValue.getTextContent().replace("\n", ""));
        return doc;
    }

    Document signResDoc(Document doc, String eln) throws Exception {
        JCPXMLDSigInit.init();
        String strDoc = Utils.dom2String(doc);
        doc = Utils.loadXMLFromString(strDoc);
        Element body = (Element) doc.getElementsByTagName("LN_RESULT").item(0);
        body.setIdAttribute("wsu:Id", true);
        final XMLSignature sig = new XMLSignature(doc, "", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element anElement = null;
        for (int i = 0; i < doc.getElementsByTagName("wsse:Security").getLength(); i++){
            Element element = (Element) doc.getElementsByTagName("wsse:Security").item(i);
            if (element.getAttribute("S:actor").contains("http://eln.fss.ru/actor/doc/" + eln + "_2_doc")){
                anElement = element;
            }
        }
        anElement.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        sig.addDocument("#ELN_" + eln + "_2_doc", transforms, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        sig.getKeyInfo();
        Element keyInfo = (Element) sig.getElement().getElementsByTagName("ds:KeyInfo").item(0);
        Element securityTokenRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/doc/" + eln + "_2_doc");
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenRef.appendChild(reference);
        keyInfo.appendChild(securityTokenRef);
        sig.sign(moPrivateKey);
        Element sigValue = (Element) doc.getElementsByTagName("ds:SignatureValue").item(0);
        sigValue.setTextContent(sigValue.getTextContent().replace("\n", ""));
        return doc;
    }

    //Подпись документа вк
    Document signDocByVk(Document doc, String eln) throws Exception {
        JCPXMLDSigInit.init();
        String strDoc = Utils.dom2String(doc);
        doc = Utils.loadXMLFromString(strDoc);
        Element body = (Element) doc.getElementsByTagName("TREAT_FULL_PERIOD").item(0);
        body.setIdAttribute("wsu:Id", true);
        final XMLSignature sig = new XMLSignature(doc, "", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element anElement = null;
        for (int i = 0; i < doc.getElementsByTagName("wsse:Security").getLength(); i++){
            Element element = (Element) doc.getElementsByTagName("wsse:Security").item(i);
            if (element.getAttribute("S:actor").contains("http://eln.fss.ru/actor/doc/" + eln + "_3_vk")){
                anElement = element;
            }
        }
        anElement.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        sig.addDocument("#ELN_" + eln + "_3_vk", transforms, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        sig.getKeyInfo();
        Element keyInfo = (Element) sig.getElement().getElementsByTagName("ds:KeyInfo").item(0);
        Element securityTokenRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/doc/" + eln + "_3_vk");
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenRef.appendChild(reference);
        keyInfo.appendChild(securityTokenRef);
        sig.sign(moPrivateKey);
        Element sigValue = (Element) doc.getElementsByTagName("ds:SignatureValue").item(0);
        sigValue.setTextContent(sigValue.getTextContent().replace("\n", ""));
        return doc;
    }

    //подпись документа Мо
    Document signDocByMo(Document doc, String eln) throws Exception {
        JCPXMLDSigInit.init();
        String strDoc = Utils.dom2String(doc);
        doc = Utils.loadXMLFromString(strDoc);
        Element body = (Element) doc.getElementsByTagName("ROW").item(0);
        body.setIdAttribute("wsu:Id", true);
        final XMLSignature sig = new XMLSignature(doc, "", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element anElement = null;
        for (int i = 0; i < doc.getElementsByTagName("wsse:Security").getLength(); i++){
            Element element = (Element) doc.getElementsByTagName("wsse:Security").item(i);
            if (element.getAttribute("S:actor").contains("http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn + "/ELN_" + eln)){
                anElement = element;
            }
        }
        anElement.appendChild(sig.getElement());
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        sig.addDocument("#ELN_" + eln, transforms, "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        sig.getKeyInfo();
        Element keyInfo = (Element) sig.getElement().getElementsByTagName("ds:KeyInfo").item(0);
        Element securityTokenRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn + "/ELN_" + eln);
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenRef.appendChild(reference);
        keyInfo.appendChild(securityTokenRef);
        sig.sign(moPrivateKey);
        Element sigValue = (Element) doc.getElementsByTagName("ds:SignatureValue").item(0);
        sigValue.setTextContent(sigValue.getTextContent().replace("\n", ""));
        return doc;
    }

    //Расшифровка
    Document decrypt(Document doc) throws Exception {
        Element encKeyElem = (Element) doc.getElementsByTagName("xenc:EncryptedKey").item(0);
        Element encryptedDataElement = (Element) doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
        XMLCipher xmlCipher = XMLCipher.getInstance();
        xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedKey encKey = xmlCipher.loadEncryptedKey(doc, encKeyElem);
        EncryptedData encData = xmlCipher.loadEncryptedData(doc, encryptedDataElement);
        XMLCipher keyCipher =  XMLCipher.getInstance();
        keyCipher.init(XMLCipher.UNWRAP_MODE, moPrivateKey);
        Key someKey = keyCipher.decryptKey(encKey, encData.getEncryptionMethod().getAlgorithm());
        xmlCipher = XMLCipher.getInstance();
        xmlCipher.init(XMLCipher.DECRYPT_MODE, someKey);
        xmlCipher.doFinal(doc, encryptedDataElement);
        return doc;
    }


}
