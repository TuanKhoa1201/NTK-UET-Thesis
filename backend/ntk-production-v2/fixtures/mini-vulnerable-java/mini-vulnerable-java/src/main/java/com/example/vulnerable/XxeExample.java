package com.example.vulnerable;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * CWE-611: XML External Entity (XXE) Injection. "Import contacts
 * from XML" feature. See README.md for details and the expected
 * OpenGrep finding.
 */
public class XxeExample {

    /** VULNERABLE: default (insecure) factory settings allow DOCTYPE + external entities. */
    public Document parseContactsXmlVulnerable(String userSuppliedXml)
            throws ParserConfigurationException, SAXException, IOException {

        // TAINT SOURCE: userSuppliedXml from an external caller,
        // e.g. an uploaded file's contents.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // SINK: parsing untrusted XML with external entities enabled.
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream input = new ByteArrayInputStream(userSuppliedXml.getBytes(StandardCharsets.UTF_8));
        return builder.parse(input);
    }

    /** SAFE: DOCTYPE disallowed outright; external entities/XInclude disabled too. */
    public Document parseContactsXmlSafe(String userSuppliedXml)
            throws ParserConfigurationException, SAXException, IOException {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Primary defense: reject any DOCTYPE outright.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // Defense in depth, in case DOCTYPE rejection is ever loosened.
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputStream input = new ByteArrayInputStream(userSuppliedXml.getBytes(StandardCharsets.UTF_8));
        return builder.parse(input);
    }
}
