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
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class CrlRevocationCheck implements Execution {

  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      String pem = messageContext.getVariable("flow.tls.client.pem");
      X509Certificate certificate = pemToCertificate(pem);

      String crlDistributionPoint = messageContext.getVariable("flow.crlDistributionPoint");
      byte[] crlDer = messageContext.getVariable("flow.crlDerFromCache");

      X509CRL crl = getCrl(crlDistributionPoint, crlDer);
      messageContext.setVariable("flow.numberOfRevokedCertificates", crl.getRevokedCertificates().size());
      messageContext.setVariable("flow.crlDer", crl.getEncoded());

      boolean res = isCertRevoked(certificate, crl);
      messageContext.setVariable("flow.isCertificateRevoked", res);

      return ExecutionResult.SUCCESS;
    } catch (Exception e) {
      messageContext.setVariable("flow.java.error", e.getMessage());
      return ExecutionResult.ABORT;
    }
  }

  private static X509CRL getCrl(String crlUrl, byte[] crlDer)
    throws MalformedURLException, IOException, CertificateException, CRLException {
    if (crlDer == null) {
      return downloadCrl(crlUrl);
    } else {
      return decodeFromDer(crlDer);
    }
  }

  private static X509CRL decodeFromDer(byte[] crlDer)
    throws CertificateException, CRLException {
    InputStream crlStream = new ByteArrayInputStream(crlDer);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509CRL) cf.generateCRL(crlStream);
  }

  private static X509CRL downloadCrl(String crlUrl)
      throws MalformedURLException, IOException, CertificateException, CRLException {
    URL url = new URL(crlUrl);
    InputStream crlStream = url.openStream();

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509CRL) cf.generateCRL(crlStream);
    } finally {
      crlStream.close();
    }
  }

  private static boolean isCertRevoked(X509Certificate certificate, X509CRL crl) throws CertificateException{
    return crl.isRevoked(certificate);
  }

  private static X509Certificate pemToCertificate(String pem) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(pem.getBytes()));
  }
}
