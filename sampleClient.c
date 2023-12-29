#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ocsp.h>
#include <openssl/bio.h>
#include <netdb.h>
#include <time.h>

// TODO: Callback function for custom certificate verification

// Function to get OCSP URL from a certificate
char* get_ocsp_url(X509 *cert) {
    AUTHORITY_INFO_ACCESS *aia = NULL;
    char *ocsp_url = NULL;

    // Retrieve the AIA extension from the certificate
    aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (aia == NULL) {
        return NULL;
    }

    // Iterate over all access descriptions in the AIA extension
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (ad == NULL) {
            continue;
        }
        // Check if the access method is for OCSP
        if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
            // If the access location is a URI, extract the URI
            if (ad->location->type == GEN_URI) {
                ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;
                ocsp_url = (char *) ASN1_STRING_get0_data(uri);
                // If a valid URI is found, duplicate it and break the loop
                if (ocsp_url != NULL) {
                    ocsp_url = strdup(ocsp_url); // Duplicate the URL
                    break;
                }
            }
        }
    }

    // Free the AIA
    AUTHORITY_INFO_ACCESS_free(aia);

    // Return the OCSP URL or NULL
    return ocsp_url;
}

// Helper function to create OCSP request
OCSP_REQUEST *create_ocsp_request(X509 *cert, X509 *issuer) {
    OCSP_REQUEST *req = NULL;
    OCSP_CERTID *id = NULL;

    // Check if issuer certificate is provided
    if (!issuer) {
        fprintf(stderr, "Issuer certificate is null.\n");
        return NULL;
    }

    // Create a new OCSP request
    req = OCSP_REQUEST_new();
    if (!req) {
        fprintf(stderr, "Failed to create OCSP request.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Create a certificate ID
    id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (!id) {
        fprintf(stderr, "Error creating OCSP certificate ID.\n");
        OCSP_REQUEST_free(req);
        return NULL;
    }

    // Add the certificate ID to the OCSP request
    if (!OCSP_request_add0_id(req, id)) {
        fprintf(stderr, "Error adding certificate ID to OCSP request.\n");
        OCSP_REQUEST_free(req);
        return NULL;
    }

    // Return the OCSP request object or NULL
    return req;
}

// Function to convert ASN1_GENERALIZEDTIME to time_t
time_t ASN1_TIME_to_time_t(ASN1_GENERALIZEDTIME *time) {
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));
    t.tm_year = (str[i++] - '0') * 1000;
    t.tm_year += (str[i++] - '0') * 100;
    t.tm_year += (str[i++] - '0') * 10;
    t.tm_year += (str[i++] - '0');
    t.tm_year -= 1900;
    t.tm_mon = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1;
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday += (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour += (str[i++] - '0');
    t.tm_min = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');

    // Return the time in time_t format
    return mktime(&t);
}

// Function to check OCSP revocation status
int check_ocsp_revocation_status(X509 *cert, X509 *issuer, time_t *revocation_time) {
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    BIO *bio = NULL;
    int status = -1; // ERROR

    // Attempt to retrieve the OCSP URL from the certificate
    char *ocsp_url = get_ocsp_url(cert);
    if (!ocsp_url) {
        fprintf(stderr, "OCSP URL not found for the certificate.\n");
        return -1;
    }

    char host[1024] = {0};
    char port[1024] = {0};

    // Parse the OCSP URL to extract host and port
    if (sscanf(ocsp_url, "http://%[^:/]:%s", host, port) != 2) {
        // Default to port 80 if not specified
        sscanf(ocsp_url, "http://%[^:/]", host);
        strcpy(port, "80");
    }

    char ocsp_conn_str[2048];
    snprintf(ocsp_conn_str, sizeof(ocsp_conn_str), "%s:%s", host, port);

    // Create the OCSP request
    req = create_ocsp_request(cert, issuer);
    if (!req) {
        free(ocsp_url);
        return -1;
    }

    // Connect to OCSP responder
    bio = BIO_new_connect(ocsp_conn_str);
    if (!bio || BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to OCSP responder: %s\n", ocsp_conn_str);
        ERR_print_errors_fp(stderr);
        OCSP_REQUEST_free(req);
        BIO_free_all(bio);
        free(ocsp_url);
        return -1;
    }

    // Send the OCSP request and receive the response
    resp = OCSP_sendreq_bio(bio, ocsp_url, req);
    if (!resp) {
        fprintf(stderr, "Failed to send OCSP request or receive response.\n");
        ERR_print_errors_fp(stderr);
        OCSP_REQUEST_free(req);
        BIO_free_all(bio);
        free(ocsp_url);
        return -1;
    }

    // Parse the OCSP response
    int result = OCSP_response_status(resp);
    if (result == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_BASICRESP *basic_resp = OCSP_response_get1_basic(resp);
        if (basic_resp) {
            OCSP_CERTID *id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
            OCSP_SINGLERESP *single_resp = OCSP_resp_get0(basic_resp, 0);

            int reason;
            ASN1_GENERALIZEDTIME *revTime;
            int cert_status = OCSP_single_get0_status(single_resp, &reason, NULL, &revTime, NULL);

            if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
                status = 1; // Certificate is revoked
                if (revTime) {
                    *revocation_time = ASN1_TIME_to_time_t(revTime);
                }
            } else {
                status = 0; // Certificate is not revoked
            }

            OCSP_CERTID_free(id);
            OCSP_BASICRESP_free(basic_resp);
        }
    }

    // Clean up
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    BIO_free_all(bio);
    free(ocsp_url);

    // Return the revocation status: 0 for not revoked, 1 for revoked, and -1 for error
    return status;
}

// Function to print CRL (Certificate Revocation List) distribution points from a certificate
void print_crl_distribution_points(X509 *cert, int depth) {
    STACK_OF(DIST_POINT) *dist_points;
    DIST_POINT *dp;
    X509_EXTENSION *ext;
    int ext_idx;

    ext_idx = X509_get_ext_by_NID(cert, NID_crl_distribution_points, -1);
    ext = X509_get_ext(cert, ext_idx);
    if (!ext) {
        if (depth == 0) {
            printf("No CRL distribution points in leaf certificate.\n");
        } else {
            X509_NAME *subj = X509_get_subject_name(cert);
            X509_NAME *issuer = X509_get_issuer_name(cert);

            if (X509_NAME_cmp(subj, issuer) == 0) {
                // Root certificate
                printf("No CRL distribution points because it is root.\n");
            } else {
                // Not a root certificate
                printf("No CRL distribution points extension found.\n");
            }
        }
        return;
    }

    dist_points = X509V3_EXT_d2i(ext);
    if (!dist_points) {
        printf("No CRL distribution points could be extracted.\n");
        return;
    }

    int num_points = sk_DIST_POINT_num(dist_points);
    if (num_points > 1) {
        printf("CRL distribution points:\n");
    }

    for (int i = 0; i < num_points; i++) {
        dp = sk_DIST_POINT_value(dist_points, i);
        if (dp->distpoint->type == 0) { // FULLNAME
            for (int j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++) {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);
                if (gen->type == GEN_URI) {
                    if (num_points == 1) {
                        printf("CRL Distribution Point: ");
                    }
                    printf("%s\n", ASN1_STRING_get0_data(gen->d.uniformResourceIdentifier));
                }
            }
        }
        if (num_points > 1) {
            printf("\n");
        }
    }

    sk_DIST_POINT_pop_free(dist_points, DIST_POINT_free);
}

// Function to print the details of a certificate
void print_certificate(X509 *cert) {
    if (cert) {
        printf("Certificate:\n");
        X509_print_fp(stdout, cert);
        printf("\n");
    }
}

// Function to print detailed information about a certificate
void print_certificate_info(X509 *cert, int depth) {
    X509_NAME *subj = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);

    char subj_str[256];
    char issuer_str[256];

    // Convert the names to a readable string
    X509_NAME_oneline(subj, subj_str, sizeof(subj_str));
    X509_NAME_oneline(issuer, issuer_str, sizeof(issuer_str));

    // Print the certificate details at the given depth
    printf("Certificate at depth: %d\n", depth);
    printf("Subject: %s\n", subj_str);
    printf("Issuer: %s\n\n", issuer_str);

    // Print CRL Distribution Points
    print_crl_distribution_points(cert, depth);

    // Print OCSP URI
    char *ocsp_uri = get_ocsp_url(cert);
    if (ocsp_uri) {
        printf("OCSP URI\n%s\n\n", ocsp_uri);
        free(ocsp_uri);
    }
}

// Function to save a certificate to a file in PEM format
void save_certificate(X509 *cert, const char *filename) {
    if (cert) {
        FILE *fp = fopen(filename, "w");
        if (fp) {
            PEM_write_X509(fp, cert);
            fclose(fp);
            printf("Saved certificate to %s\n", filename);
        } else {
            fprintf(stderr, "Could not open %s for writing.\n", filename);
        }
    }
}

// Function to check if a certificate is expired
int is_certificate_expired(X509 *cert) {
    if (!cert) {
        return -1; // Error when no certificate is provided
    }

    const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
    if (!notAfter) {
        return -1; // Error when nable to get the expiration time
    }

    // Get the current time
    time_t current_time = time(NULL);
    
    // Compare the current time with the certificate's notAfter time
    if (X509_cmp_time(notAfter, &current_time) < 0) {
        return 1; // Certificate is expired
    }

    return 0; // Certificate is not expired
}

// Callback function to handle certificate verification errors
int verify_callback(int preverify, X509_STORE_CTX *x509_ctx) {
    int error = X509_STORE_CTX_get_error(x509_ctx);

    // Preverification passed
    if (preverify == 1) {
        return 1;
    }

    // Handle specific errors
    switch (error) {
        case X509_V_ERR_CERT_HAS_EXPIRED:
            // Handle expired certificate error
            printf("Invalid Certificate Error: Certificate has expired, but continuing the verification for testing purposes.\n");
            break;
        case X509_V_ERR_CERT_REVOKED:
            // Handle revoked certificate
            printf("Invalid Certificate Error: Certificate is revoked. (detected by SSL handshake)\n");
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            // Handle self-signed certificate at depth 0
            printf("Invalid Certificate Error: Self-signed certificate encountered at depth 0.\n");
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            // Handle unable to get local issuer certificate
            printf("Invalid Certificate Error: Unable to get local issuer certificate.\n");
            break;
        case X509_V_ERR_CERT_UNTRUSTED:
            // Handle untrusted certificate
            printf("Invalid Certificate Error: Certificate is untrusted.\n");
            break;
        case X509_V_ERR_INVALID_CA:
            // Handle invalid certificate authority
            printf("Invalid Certificate Error: Invalid certificate authority.\n");
            break;
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            // Handle signature failure
            printf("Invalid Certificate Error: Signature failure.\n");
            break;
        default:
            // Handle other errors
            printf("Error: Verification failed. Error code: %d\n", error);
            break;
    }

    // Allow expired certificates and revoked certificates but no other errors (for testing purposes)
    if (error == X509_V_ERR_CERT_HAS_EXPIRED || error == X509_V_ERR_CERT_REVOKED) {
        return 1;
    }

    // By default, don't establish the connection if there are errors
    return 0;
}

// Main function
// Handles command line arguments
// Sets up SSL context
// Performs certificate verification and OCSP checking
int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    X509 *cert;
    STACK_OF(X509) *cert_chain;
    int option;
    int verbose = 0, output_files = 0;
    time_t revocation_time = 0;

    while ((option = getopt(argc, argv, "vo")) != -1) {
        switch (option) {
            case 'v': verbose = 1; break;
            case 'o': output_files = 1; break;
            default: fprintf(stderr, "Invalid option\n");
                     exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-v|-o] <host>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *host = argv[optind];

    // Initialize OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Disable certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    // TODO: Set the location of the trust store. Currently based on Debian.
    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) {
        fprintf(stderr, "Error setting up trust store.\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // TODO: automatic chain verification should be modified
    // Create a new BIO chain with an SSL BIO using the context
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set up the SSL
    BIO_get_ssl(bio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Error getting SSL.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Set the SNI hostname
    SSL_set_tlsext_host_name(ssl, host);

    // Set up the connection to the remote host
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, "443");

    // Enable OCSP stapling
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

    // Attempt to connect
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error connecting to remote host.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Attempt to do the TLS/SSL handshake
    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    long verification_result = SSL_get_verify_result(ssl);
    if (verification_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification error: %ld (%s)\n",
                verification_result, X509_verify_cert_error_string(verification_result));
    }

    // Check for stapled OCSP response
    const unsigned char *ocsp_resp;
    long ocsp_resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_resp);
    OCSP_RESPONSE *response = NULL;

    if (ocsp_resp_len > 0) {
        printf("OCSP response is stapled.\n\n");
        
        // Decode the OCSP response
        const unsigned char *p = ocsp_resp; // temporary pointer
        response = d2i_OCSP_RESPONSE(NULL, &p, ocsp_resp_len);
        if (response) {
            if (verbose) {
                OCSP_RESPONSE_print(BIO_new_fp(stdout, BIO_NOCLOSE), response, 0);
            }
            
            if (output_files) {
                // Save the OCSP response to a file
                FILE *fp = fopen("ocsp.pem", "wb");
                if (fp != NULL) {
                    const int length = i2d_OCSP_RESPONSE(response, NULL);
                    if (length > 0) {
                        unsigned char *der = malloc(length);
                        unsigned char *p = der;
                        if (i2d_OCSP_RESPONSE(response, &p) > 0) {
                            fwrite(der, 1, length, fp);
                            printf("OCSP response saved to ocsp.pem\n");
                        } else {
                            fprintf(stderr, "Error converting OCSP response to DER format.\n");
                        }
                        free(der);
                    } else {
                        fprintf(stderr, "Error determining OCSP response length.\n");
                    }
                    fclose(fp);
                } else {
                    fprintf(stderr, "Unable to open ocsp.pem for writing.\n");
                }
            }
            OCSP_RESPONSE_free(response);
        } else {
            fprintf(stderr, "Failed to decode OCSP response.\n");
        }
    } else {
        printf("No OCSP stapling response received.\n\n");
    }

    // Retrieve the certificate chain
    cert_chain = SSL_get_peer_cert_chain(ssl);
    if (cert_chain == NULL) {
        fprintf(stderr, "Error getting certificate chain.\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    int overall_ocsp_status = 0; // 0 for good, 1 for revoked

    for (int i = 0; i < sk_X509_num(cert_chain); i++) {
        cert = sk_X509_value(cert_chain, i);
        print_certificate_info(cert, i);

        // Check if the certificate is expired
        if (is_certificate_expired(cert) == 1) {
            printf("Certificate status: \033[31mEXPIRED\033[0m\n");
            exit(0);
        }

        if (output_files) {
            char filename[32];
            snprintf(filename, sizeof(filename), "depth%d.pem", i);
            save_certificate(cert, filename);
        }

        if (i < sk_X509_num(cert_chain) - 1) {
            char *ocsp_url = get_ocsp_url(cert);
            if (ocsp_url) {
                X509 *issuer_cert = sk_X509_value(cert_chain, i + 1);
                int ocsp_status = check_ocsp_revocation_status(cert, issuer_cert, &revocation_time);
                if (ocsp_status == 1) {int ocsp_status = check_ocsp_revocation_status(cert, issuer_cert, &revocation_time);

                    overall_ocsp_status = 1; // Certificate is revoked
                }
                free(ocsp_url);
            }
        }
    }

    printf("Checking OCSP...\n");

    // Check final status of the certificate chain
    if (overall_ocsp_status == 1) {
        printf("Certificate status: \033[31mREVOKED\033[0m\n");
        if (revocation_time != 0) {
            char buffer[30];
            strftime(buffer, 30, "%b %d %H:%M:%S", localtime(&revocation_time));
            printf("Revocation Time: %s\n", buffer);
        }
    } else {
        printf("Certificate status: \033[32mGOOD\033[0m\n");
    }

    // Clean up
    ERR_clear_error();
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}