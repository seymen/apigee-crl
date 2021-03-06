Feature: CRL implementation with Apigee

  Scenario: Valid non-cachable certificate with CRL distribution point
    Given I pipe contents of file valid-not-cachable.crt to body
    When I GET /crl
    Then response code should be 200
    And response body path $.crlDistributionPoint should be http://crl3.digicert.com/ssca-sha2-g5.crl
    And response body path $.numberOfRevokedCertificates should be \d+
    And response body path $.serialNumber should be 1f202031dfda98efdff0f72be51060d
    And response body path $.crlSource should be download
    And response body path $.isCertificateRevoked should be false

  Scenario: Valid cachable certificate with CRL distribution point - Request 1
    Given I pipe contents of file valid-cachable.crt to body
    When I GET /crl
    Then response code should be 200
    And response body path $.crlDistributionPoint should be http://crl3.digicert.com/sha2-ha-server-g6.crl
    And response body path $.numberOfRevokedCertificates should be \d+
    And response body path $.serialNumber should be 765c64e74e591d68039ca2a847563f0
    And response body path $.isCertificateRevoked should be false

  Scenario: Valid cachable certificate with CRL distribution point - Request 2
    Given I pipe contents of file valid-cachable.crt to body
    When I GET /crl
    Then response code should be 200
    And response body path $.crlDistributionPoint should be http://crl3.digicert.com/sha2-ha-server-g6.crl
    And response body path $.numberOfRevokedCertificates should be \d+
    And response body path $.serialNumber should be 765c64e74e591d68039ca2a847563f0
    And response body path $.crlSource should be cache
    And response body path $.isCertificateRevoked should be false

  Scenario: Revoked certificate
    Given I pipe contents of file revoked.crt to body
    When I GET /crl
    Then response code should be 400
    And response body path $.message should be Certificate has been revoked

  Scenario: Valid certificate with no CRL distribution points
    Given I pipe contents of file no-crl.crt to body
    When I GET /crl
    Then response code should be 400
    And response body path $.message should be There are no CRL distribution points defined for this certificate

  Scenario: Valid certificate with invalid CRL distribution point
    Given I pipe contents of file invalid-dp.crt to body
    When I GET /crl
    Then response code should be 400
    And response body path $.message should be Certificate CRL distribution point is invalid

  Scenario: Valid certificate with malformed CRL distribution point
    Given I pipe contents of file malformed-dp.crt to body
    When I GET /crl
    Then response code should be 400
    And response body path $.message should be Certificate CRL distribution point is invalid
