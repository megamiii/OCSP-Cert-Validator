# OCSP-Cert-Validator

## Development Environment
- **Operating System:** Ubuntu 20.04.6 LTS (Focal Fossa)
- **Compiler:** GCC 9.4.0
- **Libraries Used:** OpenSSL 1.1.1f  [31 Mar 2020]
- **Dependencies:** Standard libraries, OpenSSL development libraries, POSIX-compliant system libraries.

## Compilation Command
```sh
gcc sampleClient.c -o sampleClient -lssl -lcrypto
```

## Executiom Instructions
To run the SSL Certificate Validation Tool, use the following command:
```sh
./sampleClient <host>
```

- **<host>:** Replace with the domain or IP address of the server whose certificate you wish to validate.

For verbose output, showing detailed certificate information:
```sh
./sampleClient -v <host>
```

To save the certificates to files:
```sh
./sampleClient -o <host>
```

## Description
OCSP-Cert-Validator is a tool designed for validating SSL certificates using OCSP. It connects to servers, retrieves certificate chains, checks revocation status, and provides detailed insights. Ideal for ensuring secure TLS connections and certificate authenticity. Includes verbose output and save options.

## Features
- Retrieves server's certificate chain during TLS handshake.
- Performs OCSP stapling handling.
- Validates certificates against the trusted root store.
- Checks for certificate revocation via OCSP or CRL.
- Provides options for verbose output and saving certificates to files.

## Source Code Structure
The source code is structured as follows:

- **Main Functions:**
  - `main()`: Entry point of the program. It handles the SSL connection setup, certificate retrieval, and verification process.

- **Certificate Verification:**
  - `verify_callback()`: Custom callback function for certificate verification during the SSL handshake.

- **OCSP Handling:**
  - `get_ocsp_url()`: Retrieves the OCSP URL from a certificate.
  - `create_ocsp_request()`: Creates an OCSP request for a given certificate and issuer.
  - `check_ocsp_revocation_status()`: Checks the revocation status of a certificate using the OCSP protocol.

- **Certificate and CRL Information:**
  - `print_certificate()`: Prints a human-readable representation of a certificate.
  - `print_certificate_info()`: Prints detailed information about a certificate, including subject and issuer.
  - `print_crl_distribution_points()`: Prints the CRL distribution points from a certificate.
  - `save_certificate()`: Saves a certificate to a file in PEM format.

- **Time Conversion:**
  - `ASN1_TIME_to_time_t()`: Converts ASN1_GENERALIZEDTIME to time_t, which is a POSIX standard for representing time.

- **Utility Functions:**
  - `is_certificate_expired()`: Checks if the certificate is expired by comparing its validity period with the current time.

- **OpenSSL Initializations:**
  - Initialization functions like `SSL_load_error_strings()`, `ERR_load_BIO_strings()`, `OpenSSL_add_all_algorithms()`, and `SSL_library_init()` are called to set up the necessary OpenSSL environment.

- **SSL Context and Connection:**
  - SSL context (`SSL_CTX`) is created and configured.
  - BIO chain is set up for the SSL connection.
  - SSL handshake is performed and certificate chain is retrieved.
  - Checks for stapled OCSP response.
  
- **OCSP Stapling:**
  - `SSL_set_tlsext_status_type()`: Configures the SSL to request for OCSP stapling.
  
- **Error Handling:**
  - Prints out errors encountered during SSL connection setup, OCSP handling, and certificate processing.

## Test Cases
**1. Expired Certificate (expired-ecc-dv.ssl.com)** 
```sh
./sampleClient expired-ecc-dv.ssl.com
Invalid Certificate Error: Certificate has expired, but continuing the verification for testing purposes.
Certificate verification error: 10 (certificate has expired)
No OCSP stapling response received.

Certificate at depth: 0
Subject: /CN=expired-ecc-dv.ssl.com
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corp/CN=SSL.com SSL Intermediate CA ECC R2

CRL Distribution Point: http://crls.ssl.com/SSLcom-SubCA-SSL-ECC-384-R2.crl
OCSP URI
http://ocsps.ssl.com

Certificate status: EXPIRED
```
**2. Revoked Certificate (revoked-rsa-dv.ssl.com)** 
```sh
./sampleClient revoked-rsa-dv.ssl.com
No OCSP stapling response received.

Certificate at depth: 0
Subject: /CN=revoked-rsa-dv.ssl.com
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com RSA SSL subCA

CRL Distribution Point: http://crls.ssl.com/SSLcom-SubCA-SSL-RSA-4096-R1.crl
OCSP URI
http://ocsps.ssl.com

Certificate at depth: 1
Subject: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com RSA SSL subCA
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com Root Certification Authority RSA

CRL Distribution Point: http://crls.ssl.com/ssl.com-rsa-RootCA.crl
OCSP URI
http://ocsps.ssl.com

Certificate at depth: 2
Subject: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com Root Certification Authority RSA
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com Root Certification Authority RSA

No CRL distribution points because it is root.
Checking OCSP...
Certificate status: REVOKED
Revocation Time: Nov 24 09:55:45
```
**3. Valid Certificate (www.google.com)** 
```sh
./sampleClient www.google.com
No OCSP stapling response received.

Certificate at depth: 0
Subject: /CN=www.google.com
Issuer: /C=US/O=Google Trust Services LLC/CN=GTS CA 1C3

CRL Distribution Point: http://crls.pki.goog/gts1c3/zdATt0Ex_Fk.crl
OCSP URI
http://ocsp.pki.goog/gts1c3

Certificate at depth: 1
Subject: /C=US/O=Google Trust Services LLC/CN=GTS CA 1C3
Issuer: /C=US/O=Google Trust Services LLC/CN=GTS Root R1

CRL Distribution Point: http://crl.pki.goog/gtsr1/gtsr1.crl
OCSP URI
http://ocsp.pki.goog/gtsr1

Certificate at depth: 2
Subject: /C=US/O=Google Trust Services LLC/CN=GTS Root R1
Issuer: /C=BE/O=GlobalSign nv-sa/OU=Root CA/CN=GlobalSign Root CA

CRL Distribution Point: http://crl.pki.goog/gsr1/gsr1.crl
OCSP URI
http://ocsp.pki.goog/gsr1

Checking OCSP...
Certificate status: GOOD
```
**4. Valid Certificate (test-ev-rsa.ssl.com)**
```sh
./sampleClient test-ev-rsa.ssl.com
No OCSP stapling response received.

Certificate at depth: 0
Subject: /C=US/ST=Texas/L=Houston/O=SSL.com (SSL Corp)/serialNumber=NV20081614243/CN=test-ev-rsa.ssl.com/businessCategory=Private Organization/jurisdictionST=Nevada/jurisdictionC=US
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corp/CN=SSL.com EV SSL Intermediate CA RSA R3

CRL Distribution Point: http://crls.ssl.com/SSLcom-SubCA-EV-SSL-RSA-4096-R3.crl
OCSP URI
http://ocsps.ssl.com

Certificate at depth: 1
Subject: /C=US/ST=Texas/L=Houston/O=SSL Corp/CN=SSL.com EV SSL Intermediate CA RSA R3
Issuer: /C=US/ST=Texas/L=Houston/O=SSL Corporation/CN=SSL.com EV Root Certification Authority RSA R2

CRL Distribution Point: http://crls.ssl.com/SSLcom-RootCA-EV-RSA-4096-R2.crl
OCSP URI
http://ocsps.ssl.com

Checking OCSP...
Certificate status: GOOD
```