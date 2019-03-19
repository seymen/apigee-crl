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
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

public class CrlRevocationCheck implements Execution {

  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      // load the incoming cert in PEM format and read standard attributes
      String pem = messageContext.getVariable("custom.tls.client.pem");
      X509Certificate certificate = Utils.pemToCertificate(pem);
      messageContext.setVariable("custom.serialNumber", certificate.getSerialNumber().toString(16));

      // read the CRL distribution point extracted in previous java callout
      String crlDistributionPoint = messageContext.getVariable("custom.crlDistributionPoint");

      // read the CRL binary from cache if it has been cached in previous requests
      byte[] crlDer = messageContext.getVariable("custom.internal.crlDerFromCache");
      if (crlDer != null) {
        messageContext.setVariable("custom.internal.crlSource", "cache");
      } else {
        messageContext.setVariable("custom.internal.crlSource", "download");
      }

      // load the CRL binary into an instance of X509CRL class
      X509CRL crl = getCrl(crlDistributionPoint, crlDer);
      messageContext.setVariable("custom.numberOfRevokedCertificates", crl.getRevokedCertificates().size());
      messageContext.setVariable("custom.internal.crlDer", crl.getEncoded());
      messageContext.setVariable("custom.internal.crlDerSize", crl.getEncoded().length);

      // check revocation
      boolean isCertRevoked = isCertRevoked(certificate, crl);
      messageContext.setVariable("custom.isCertificateRevoked", isCertRevoked);
      if (isCertRevoked) {
        throw new BadRequestException("Certificate has been revoked");
      }

      return ExecutionResult.SUCCESS;
    } catch (BadRequestException bad) {
      messageContext.setVariable("custom.error.message", bad.getMessage());
      messageContext.setVariable("custom.error.internal", Utils.getStackTrace(bad));
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      messageContext.setVariable("custom.error.internal", Utils.getStackTrace(e));
      return ExecutionResult.ABORT;
    }
  }

  protected static X509CRL getCrl(String crlUrl, byte[] crlDer)
    throws IOException, CertificateException, CRLException, BadRequestException {
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
      throws IOException, CertificateException, CRLException, BadRequestException {

    InputStream crlStream = null;

    try {
      URL url = new URL(crlUrl);

      URLConnection con = url.openConnection();
      con.setConnectTimeout(1000);
      con.setReadTimeout(2000);
      crlStream = con.getInputStream();

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509CRL) cf.generateCRL(crlStream);
    } catch (MalformedURLException | UnknownHostException | CRLException e) {
      throw new BadRequestException("Certificate CRL distribution point is invalid");
    } finally {
      if (crlStream != null)
        crlStream.close();
    }
  }

  protected static boolean isCertRevoked(X509Certificate certificate, X509CRL crl) throws CertificateException{
    return crl.isRevoked(certificate);
  }
}
