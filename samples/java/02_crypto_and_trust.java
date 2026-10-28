/* Weak crypto, hard-coded key, unsafe deserialization, XXE, trust-all TLS and an open redirect */
package com.example.security;

import java.io.*;
import java.security.MessageDigest;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.servlet.http.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class LegacyGateway {
    private static final Logger LOG = Logger.getLogger("gateway");
    private static final byte[] KEY = "0123456789abcdef".getBytes();

    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        LOG.info("hashing password " + password);
        return new String(md.digest(password.getBytes()));
    }

    public byte[] encrypt(byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec("s3cr3t-k3y-2024!".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public Object restoreSession(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();
    }

    public Document parseInvoice(InputStream xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xml);
    }

    public void disableCertificateChecks() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("SSL");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
    }

    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String next = request.getParameter("next");
        Cookie session = new Cookie("SESSIONID", Long.toString(System.nanoTime()));
        response.addCookie(session);
        response.sendRedirect(next);
    }

    public Object loadPlugin(HttpServletRequest request) throws Exception {
        String plugin = request.getParameter("plugin");
        return Class.forName(plugin).getDeclaredConstructor().newInstance();
    }
}
