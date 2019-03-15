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
      String pem = messageContext.getVariable("custom.tls.client.pem");
      X509Certificate certificate = pemToCertificate(pem);
      String crlDistributionPoint = getCrlDistributionPoint(certificate);

      messageContext.setVariable("custom.crlDistributionPoint", crlDistributionPoint);

      return ExecutionResult.SUCCESS;
    } catch (BadRequestException bad) {
      messageContext.setVariable("custom.error.message", bad.getMessage());
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      messageContext.setVariable("custom.internal.error.message", e.getMessage());
      return ExecutionResult.ABORT;
    }
  }

  protected static X509Certificate pemToCertificate(String pem) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pem.getBytes()));
  }

  protected static String getCrlDistributionPoint(X509Certificate certificate)
    throws IOException, CertificateException, BadRequestException {
    ASN1InputStream oAsnInStream = null;
    ASN1InputStream oAsnInStream2 = null;

    try {
      byte[] crlDistributionPointDerEncodedArray = certificate
        .getExtensionValue(Extension.cRLDistributionPoints.getId());

      if (crlDistributionPointDerEncodedArray == null) {
        throw new BadRequestException("There are no CRL distribution points defined for this certificate");
      }

      System.out.println("1: " + crlDistributionPointDerEncodedArray);

      oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointDerEncodedArray));
      ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
      DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;

      byte[] crldpExtOctets = dosCrlDP.getOctets();
      oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
      ASN1Primitive derObj2 = oAsnInStream2.readObject();
      CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

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
    } finally {
      if (oAsnInStream != null)
        oAsnInStream.close();
      if (oAsnInStream2 != null)
        oAsnInStream2.close();
    }
  }

}
