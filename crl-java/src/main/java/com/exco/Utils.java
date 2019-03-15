package com.exco;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.PrintWriter;

public class Utils {
  protected static X509Certificate pemToCertificate(String pem) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(pem.getBytes()));
  }

  protected static String getStackTrace(Exception e) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    return sw.toString();
  }
}
