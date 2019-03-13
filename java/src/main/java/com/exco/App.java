package com.exco;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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

public class App implements Execution
{
  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      String pem = messageContext.getVariable("request.content");
      X509Certificate certificate = pemToCertificate(pem);

      String crlDistributionPoint = getCrlDistributionPoint(certificate);
      X509CRL crl = downloadCRLFromWeb(crlDistributionPoint);
      boolean res = isCertRevoked(certificate, crl);

      messageContext.setVariable("flow.exco.isCertRevoked", res);

      return ExecutionResult.SUCCESS;
    } catch (Exception e) {
      messageContext.setVariable("flow.exco.java.error", e.getMessage());
      return ExecutionResult.ABORT;
    }
  }

  private static X509Certificate pemToCertificate(String pem) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(pem.getBytes()));
  }

  private static boolean isCertRevoked(X509Certificate certificate, X509CRL crl) throws CertificateException{
    return crl.isRevoked(certificate);
  }

  private static X509CRL downloadCRLFromWeb(String crlURL)
      throws MalformedURLException, IOException, CertificateException, CRLException {
    URL url = new URL(crlURL);
    InputStream crlStream = url.openStream();
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509CRL) cf.generateCRL(crlStream);
    } finally {
      crlStream.close();
    }
  }

  public static String getCrlDistributionPoint(X509Certificate certificate) {
    try {
      byte[] crlDistributionPointDerEncodedArray = certificate
          .getExtensionValue(Extension.cRLDistributionPoints.getId());

      ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray));
      ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
      DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;

      oAsnInStream.close();

      byte[] crldpExtOctets = dosCrlDP.getOctets();
      ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
      ASN1Primitive derObj2 = oAsnInStream2.readObject();
      CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

      oAsnInStream2.close();

      List<String> crlUrls = new ArrayList<String>();
      for (DistributionPoint dp : distPoint.getDistributionPoints()) {
        DistributionPointName dpn = dp.getDistributionPoint();
        // Look for URIs in fullName
        if (dpn != null) {
          if (dpn.getType() == DistributionPointName.FULL_NAME) {
            GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
            // Look for an URI
            for (int j = 0; j < genNames.length; j++) {
              if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) {
                String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                crlUrls.add(url);
              }
            }
          }
        }
      }

      // for (String url : crlUrls)
      // System.out.println(url);

      return crlUrls.get(0);
    } catch (Throwable e) {
      e.printStackTrace();
      return null;
    }
  }
}
