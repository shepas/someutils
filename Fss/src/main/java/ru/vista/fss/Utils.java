package ru.vista.fss;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.Charset;

import static ru.CryptoPro.JCPxml.Utils.createDocFactory;

/**
 * Created by Sony on 28.11.2017.
 * Утилиты
 */
class Utils {
    static String logDir = "C:\\vistafss\\log.xml";

    static Document createDoc(Document doc) throws ParserConfigurationException {
        DocumentBuilderFactory dbf = createDocFactory();
        Document document = dbf.newDocumentBuilder().newDocument();
        Element root = document.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soapenv:Envelope");
        document.appendChild(root);
        root.appendChild(document.createTextNode("\n"));
        Element header = document.createElement("soapenv:Header");
        root.appendChild(header);
        root.appendChild(document.createTextNode("\n"));
        Element body = document.createElement("soapenv:Body");
        Element encData = (Element) doc.getElementsByTagName("xenc:EncryptedData").item(0);
        Node copyNode = document.importNode(encData, true);
        body.appendChild(copyNode);
        root.appendChild(body);
        root.appendChild(document.createTextNode("\n"));
        return document;
    }

    static String dom2String(Document doc) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        return writer.getBuffer().toString();
    }

    static String node2String(Element element) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.getBuffer().toString().replaceAll("\n|\r", "");
    }

    static Document loadXMLFromString(String xml) throws Exception
    {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes()));
    }

    static SOAPMessage string2SoapMessage(String xml) throws SOAPException, IOException {
        MessageFactory factory = MessageFactory.newInstance();
        return factory.createMessage(new MimeHeaders(), new ByteArrayInputStream(xml.getBytes(Charset.forName("UTF-8"))));
    }

    static void writeDoc(Document doc, OutputStream out) throws TransformerException, IOException {
        FileWriter writer = new FileWriter(new File(logDir), true);
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        writer.close();
    }
}
