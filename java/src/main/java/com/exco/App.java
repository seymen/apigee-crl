package com.exco;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class App
{
  private static String pemFilePath = "../test/features/fixtures/";

  public static void main(String[] args) {
    pemFilePath += args[0];

    try {
      String pem = new String(Files.readAllBytes(Paths.get(pemFilePath)));
      X509Certificate certificate = CrlDistributionPointResolver.pemToCertificate(pem);

      String crlDistributionPoint = CrlDistributionPointResolver.getCrlDistributionPoint(certificate);
      System.out.println("Crl distribution point: " + crlDistributionPoint);

      X509CRL crl = CrlRevocationCheck.getCrl(crlDistributionPoint, null);
      System.out.println("Number of revoked certificates in this CRL: " + crl.getRevokedCertificates().size());

      boolean res = CrlRevocationCheck.isCertRevoked(certificate, crl);
      System.out.println("Is certificate revoked: " + res);

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
