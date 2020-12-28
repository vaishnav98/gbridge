/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Author: Christopher Friedt
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 */

#ifndef CONTROLLERS_TLS_H_
#define CONTROLLERS_TLS_H_

/**
 * @brief Initialize Gbridge TLS certificates.
 *
 * Gbridge supports standard TLS v1.2 authentication and encryption.
 *
 * The @p ca_cert parameter is required if the device (server) is using a
 * self-signed certificate. Otherwise, @p ca_cert should be `NULL`. In the
 * TLS protocol, gbridge (the client) must authenticate the certificate
 * (public key) of the device (server).
 *
 * When the device (server) is configured to authenticate gbridge (the client)
 * then gbridge must provide @p client_cert certificate (public key) and
 * @p client_key (private key). Otherwise, @p client_cert and @p client_key
 * may be `NULL`.
 *
 * @param ca_cert path name of the CA certificate in DER format
 * @param client_cert path name of the client certificate in DER format
 * @param client_key path name of the client key in DER format
 *
 * For more information, see <a href="https://tools.ietf.org/html/rfc5246">
 * RFC 5246</a>.
 */
int gbridge_tls_init(const char *ca_cert, const char *client_cert, const char *client_key);

#endif /* CONTROLLERS_TLS_H_ */
