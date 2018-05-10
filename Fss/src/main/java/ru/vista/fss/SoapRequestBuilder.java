package ru.vista.fss;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import sun.misc.BASE64Encoder;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.security.cert.X509Certificate;

import static ru.CryptoPro.JCPxml.Utils.createDocFactory;

/**
 * Created by Sony on 27.11.2017.
 */

public class SoapRequestBuilder {
    SoapRequestBuilder(){
    }

    Document createDoc() throws Exception {
        DocumentBuilderFactory dbf = createDocFactory();
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setCoalescing(true);
        dbf.setNamespaceAware(true);
        Document document = dbf.newDocumentBuilder().newDocument();
        Element root = document.createElement("S:Envelope");
        root.setAttribute("xmlns:S", "http://schemas.xmlsoap.org/soap/envelope/");
        root.setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
        root.setAttribute("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        root.setAttribute("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        root.setAttribute("xmlns:eln", "http://ru/ibs/fss/ln/ws/FileOperationsLn.wsdl");
        document.appendChild(root);
        Element header = document.createElement("S:Header");
        Element security = document.createElement("wsse:Security");
        security.setAttribute("S:actor", "http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn);
        Element binarySecToken = document.createElement("wsse:BinarySecurityToken");
        binarySecToken.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        binarySecToken.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        binarySecToken.setAttribute("wsu:Id", "SenderCertificate");
        binarySecToken.setIdAttribute("wsu:Id", true);
        security.appendChild(binarySecToken);
        header.appendChild(security);
        root.appendChild(header);
        Element body = document.createElement("S:Body");
        body.setAttribute("wsu:Id", "OGRN_" + StaticsVariables.moOgrn);
        body.setIdAttribute("wsu:Id", true);
        Element newLn = document.createElement("eln:getNewLNNum");
        Element ogrn = document.createElement("eln:ogrn");
        ogrn.setTextContent(StaticsVariables.moOgrn);
        newLn.appendChild(ogrn);
        body.appendChild(newLn);
        root.appendChild(body);
        return document;
    }

    Document createCertificateMO(Document doc, X509Certificate moCert) throws Exception {
        Element binTocken = (Element) doc.getElementsByTagName("wsse:BinarySecurityToken").item(0);
        BASE64Encoder encoder = new BASE64Encoder();
        binTocken.setTextContent(encoder.encodeBuffer(moCert.getEncoded()).replace("\r", ""));
        return doc;
    }

    Document createSecurityElement(Document doc) throws Exception {
        Element security = (Element) doc.getElementsByTagName("wsse:Security").item(0);
        Element signature = doc.createElement("ds:Signature");
        Element signedInfo = doc.createElement("ds:SignedInfo");
        Element canonisationMethod = doc.createElement("ds:CanonicalizationMethod");
        canonisationMethod.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
        Element signatureMethod = doc.createElement("ds:SignatureMethod");
        signatureMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411");
        Element sigRef = doc.createElement("ds:Reference");
        sigRef.setAttribute("URI", "#OGRN_" + StaticsVariables.moOgrn);
        Element tranforms = doc.createElement("ds:Transforms");
        Element tranform = doc.createElement("ds:Transform");
        tranform.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
        tranforms.appendChild(tranform);
        sigRef.appendChild(tranforms);
        Element digMethod = doc.createElement("ds:DigestMethod");
        digMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#gostr3411");
        Element digValue = doc.createElement("ds:DigestValue");
        sigRef.appendChild(digMethod);
        sigRef.appendChild(digValue);
        signedInfo.appendChild(canonisationMethod);
        signedInfo.appendChild(signatureMethod);
        signedInfo.appendChild(sigRef);
        Element signatureValue = doc.createElement("ds:SignatureValue");
        Element keyInfo = doc.createElement("ds:KeyInfo");
        Element secTocRef = doc.createElement("wsse:SecurityTokenReference");
        Element reference = doc.createElement("wsse:Reference");
        reference.setAttribute("URI", "#http://eln.fss.ru/actor/mo/" + StaticsVariables.moOgrn);
        reference.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        secTocRef.appendChild(reference);
        keyInfo.appendChild(secTocRef);
        signature.appendChild(signedInfo);
        signature.appendChild(signatureValue);
        signature.appendChild(keyInfo);
        security.appendChild(signature);

        return doc;
    }


}
