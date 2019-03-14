package com.exco;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class CrlDistributionPointResolver implements Execution {

  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      String pem = messageContext.getVariable("flow.tls.client.pem");
      X509Certificate certificate = pemToCertificate(pem);
      String crlDistributionPoint = getCrlDistributionPoint(certificate);

      messageContext.setVariable("flow.crlDistributionPoint", crlDistributionPoint);

      return ExecutionResult.SUCCESS;
    } catch (Exception e) {
      messageContext.setVariable("flow.java.error", e.getMessage());
      return ExecutionResult.ABORT;
    }
  }

  private static X509Certificate pemToCertificate(String pem) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pem.getBytes()));
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
