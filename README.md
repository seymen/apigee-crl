# CRL implementation for Apigee

A reference implementation to demonstrate MTLS certificate revocation check in Apigee proxies.

## Repo Structure

This repository consists of 3 parts:

*   `crl-java`: Java code that implements the CRL revocation check functionality.
*   `crl-shared`: A shared flow that can be used in your Apigee proxies.
*   `crl-proxy`: An Apigee proxy implementation that uses `crl-shared` shared flow to demonstrate how everything fits together.

## Installation

0.  **Make sure java and maven are installed**

1.  **Install Apigee Maven dependencies to your local repository**

    Apigee Java Callout dependencies are not published in Maven public repositories. Follow the steps below to install them in your local maven repository:

    ```
    cd apigee-java-deps
    ./install.sh
    ```

2.  **Build and deploy**

    ```
    mvn clean install -P{env} \
      -Dapigee.org={org} \
      -Dapigee.username={username} \
      -Dapigee.password={password}
    ```

    Note: It is recommended to use ~/.m2/settings.xml for Apigee credentials

## Shared Flow Output Variables

The shared flow sets the following variables:

| Name                               | Description                                                        |
| ---                                | ---                                                                |
| custom.serialNumber                | Serial number of the input certificate                             |
| custom.crlDistributionPoint        | CRL distribution point URL as extracted from the input certificate |
| custom.numberOfRevokedCertificates | Number of revoked certificates contained within the CRL            |
| custom.isCertificateRevoked        | Whether the input certificate has been revoked or not              |

## Implementation Notes

### Input certificate variable

Shared flow reads the input certificate from a variable called `custom.tls.client.pem`. By default, the value of this variable is set to the value of `tls.client.raw.cert` which is an out of the box Apigee variable that contains the PEM formatted client certificate when MTLS is configured on the northbound.

However, if you want the shared flow to read the input certificate from another location, e.g. request body, then you can use an AssignMessage policy before the Shared Flow execution and set `custom.tls.client.pem` to that value.

```
<AssignMessage name="AssignMessage.UsePemInRequestContent">
  <AssignVariable>
    <Name>custom.tls.client.pem</Name>
    <Ref>request.content</Ref>
  </AssignVariable>
</AssignMessage>
```
If `custom.tls.client.pem` variable is populated before the shared flow execution, that value will be used by the shared flow for CRL revocation checks.

### Caching

Shared flow makes an HTTP call to the CRL distribution point to download the list of revoked certificates. As this operation is expensive, it caches the response of that HTTP request for later use. The default value for the cache expiry is 1 hour.

## Testing

Tests can be executed as follows:

1.  **Go in the test folder**

    ```
    cd test
    ```

2.  **Install node dependencies**

    ```
    npm install
    ```

3.  **Configure**

    Edit `config.js` and change the protocol and host depending on your Apigee installation.

4. **Run tests**

    ```
    npm test
    ```
