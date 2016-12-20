#ifndef TLS_CA_H
#define TLS_CA_H

/* This file defines the CA certificate of the server.
 * It should be defined as a PEM-style certificate string.
 *
 * Note: the string should at least have a <CR><LF> newline after
 * the '-----BEGIN CERTIFICATE-----' part.
 */

/** The root-ca to trust.
 *
 * Note: the library uses sizeof(TLS_CA), so the certificate chain should
 * be defined as a char[], NOT as a char*.
 *
 * This is because mbedTLS expects a buffer with the string length + 1
 * as its size.
 */
const char TLS_CA[] =
"-----BEGIN CERTIFICATE-----\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"0000000000000InsertYourBase64EncodedCertificateHere0000000000000\r\n"
"00==\r\n"
"-----END CERTIFICATE-----\r\n";


#endif
