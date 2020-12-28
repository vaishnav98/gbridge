/*
 * GBridge (Greybus Bridge)
 * Copyright (c) 2019-2020 Friedt Professional Engineering Services, Inc
 *
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
 */

/* This file is based on tcpip.c */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

#include <debug.h>
#include <gbridge.h>
#include <controller.h>

#include "tls.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

extern int asprintf(char **strp, const char *fmt, ...);

struct tls_connection {
	int sock;
};

struct tls_device {
	char *host_name;
	char addr[AVAHI_ADDRESS_STR_MAX];
	int family;
	int port;
	SSL_CTX *ctx;
	BIO *bio;
	SSL *ssl;
};

struct tls_controller {
	AvahiClient *client;
	AvahiSimplePoll *simple_poll;
};

static const char *gbridge_tls_ca_cert;
static const char *gbridge_tls_client_cert;
static const char *gbridge_tls_client_key;

static int guess_key_format(const char *fn)
{
	struct strval {
		const char *s;
		int v;
	};

	/* add to this as necessary */
	static const struct strval strval[] = {
		{ ".pem", SSL_FILETYPE_PEM },
		{ ".der", SSL_FILETYPE_ASN1 },
	};

	size_t M;
	size_t N;
	size_t i;
	const char *ext;

	if (fn == NULL) {
		return -EINVAL;
	}

	N = strlen(fn);

	for(i = 0; i < ARRAY_SIZE(strval); ++i) {
		ext = strval[i].s;
		M = strlen(ext);
		if (N < M) {
			continue;
		}
		if (strncasecmp(ext, &fn[N - M], M) == 0) {
			return strval[i].v;
		}
	}

	return -EINVAL;
}

int gbridge_tls_init(const char *ca_cert, const char *client_cert, const char *client_key)
{
	int ret;

	ret = SSL_library_init();
	if (ret <= 0) {
		pr_err("SSL_library_init() failed (%d)\n", ret);
		goto ssl_err;
	}

	ret = SSL_load_error_strings();
	if (ret <= 0) {
		pr_err("SSL_load_error_strings() failed (%d)\n", ret);
		goto ssl_err;
	}

	ret = OpenSSL_add_ssl_algorithms();
	if (ret <= 0) {
		pr_err("OpenSSL_add_ssl_algorithms() failed (%d)\n", ret);
		goto ssl_err;
	}

	if (ca_cert == NULL) {
		pr_warn("No ca_cert provided. This implies server (device) "
			"certificates are signed by a globally verifiable certificate "
			"authority. If that is not the case, please provide the CA cert "
			"used to sign the server (device) certificate\n");
	} else {
		/* OpenSSL has no facility to load a CA cert in .der format so check
		 * we're using .pem */
		ret = guess_key_format(ca_cert);
		if (ret != SSL_FILETYPE_PEM) {
			pr_err("Provided ca_cert does not end with '.pem'\n");
			pr_err("Please convert with the following:\n");
			pr_err("openssl x509 -inform der -in ca.der -out ca.pem\n");
			ret = -EINVAL;
			goto out;
		}
	}

	if ((client_cert == NULL && client_key != NULL)
		|| (client_cert != NULL && client_key == NULL)) {
		pr_err("one of client_cert or client_key are NULL\n");
		ret = -EINVAL;
		goto out;
	}

	if (client_cert != NULL) {
		ret = guess_key_format(client_cert);
		if (ret < 0) {
			pr_err("unsupported format for client_cert\n");
			ret = -EINVAL;
			goto out;
		}
	}

	if (client_key!= NULL) {
		ret = guess_key_format(client_key);
		if (ret < 0) {
			pr_err("unsupported format for client_key\n");
			ret = -EINVAL;
			goto out;
		}
	}

	gbridge_tls_ca_cert = ca_cert;
	gbridge_tls_client_cert = client_cert;
	gbridge_tls_client_key = client_key;

	ret = 0;
	goto out;

ssl_err:
	ERR_print_errors_fp(stderr);
	if (ret == 0) {
		ret = -EIO;
	}

out:
	return ret;
}

static int tls_connection_create(struct connection *conn)
{
	int ret = -EIO;
	struct tls_connection *tconn;
	struct tls_device *td = conn->intf2->priv;
	const SSL_METHOD *method;
	X509 *cert;
	char *hostname = NULL;

	tconn = malloc(sizeof(*tconn));
	if (!tconn) {
		ret = -ENOMEM;
		goto out;
	}

	conn->priv = tconn;

	switch(td->family) {
	case AF_INET:
		asprintf(&hostname, "%s:%d", td->addr, td->port);
		break;
	case AF_INET6:
		asprintf(&hostname, "[%s]:%d", td->addr, td->port);
		break;
	default:
		return -EINVAL;
	}

	method = TLS_client_method();
	if (method == NULL) {
		pr_err("TLS_client_method() failed\n");
		goto ssl_err;
	}

	td->ctx = SSL_CTX_new(method);
	if (td->ctx == NULL) {
		pr_err("SSL_CTX_new() failed\n");
		goto ssl_err;
	}

	if (gbridge_tls_ca_cert != NULL) {
		SSL_CTX_set_verify(td->ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(td->ctx, 4);

		ret = SSL_CTX_load_verify_locations(td->ctx, gbridge_tls_ca_cert, NULL);
		if (ret <= 0) {
			pr_err("SSL_CTX_load_verify_locations() failed (%d)\n", ret);
			goto ssl_err;
		}
	}

	SSL_CTX_set_options(td->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
		| SSL_OP_NO_COMPRESSION | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3);

	if (gbridge_tls_client_cert != NULL) {
		ret = SSL_CTX_use_certificate_file(td->ctx, gbridge_tls_client_cert,
			guess_key_format(gbridge_tls_client_cert));
		if (ret <= 0) {
			pr_err("SSL_CTX_use_certificate_file() failed (%d)\n", ret);
			goto ssl_err;
		}
	}

	if (gbridge_tls_client_key != NULL) {
		ret = SSL_CTX_use_PrivateKey_file(td->ctx, gbridge_tls_client_key,
			guess_key_format(gbridge_tls_client_key));
		if (ret <= 0) {
			pr_err("SSL_CTX_use_PrivateKey_file() failed (%d)\n", ret);
			goto ssl_err;
		}
	}

	td->bio = BIO_new_ssl_connect(td->ctx);
	if (td->bio == NULL) {
		pr_err("BIO_new_ssl_connect() failed\n");
		goto ssl_err;
	}

	ret = BIO_set_conn_hostname(td->bio, hostname);
	if (ret <= 0) {
		pr_err("BIO_set_conn_address() failed (%d)\n", ret);
		goto ssl_err;
	}

	ret = BIO_get_ssl(td->bio, &td->ssl);
	if (ret <= 0) {
		pr_err("BIO_get_ssl() failed (%d)\n", ret);
		goto ssl_err;
	}

	/* SSL_set_tlsext_host_name() ? */

	ret = BIO_do_connect(td->bio);
	if (ret <= 0) {
		pr_err("BIO_do_connect() failed (%d)\n", ret);
		goto ssl_err;
	}

	ret = BIO_do_handshake(td->bio);
	if (ret <= 0) {
		pr_err("BIO_do_handshake() failed (%d)\n", ret);
		goto ssl_err;
	}

	/* 1. verify server certificate was presented */
	cert = SSL_get_peer_certificate(td->ssl);
	if (cert == NULL) {
		pr_err("SSL_get_peer_certificate() failed\n");
		goto ssl_err;
	} else {
		free(cert);
	}

	/* 2. chain verification performed according to RFC 4158 */
	ret = SSL_get_verify_result(td->ssl);
	if (ret != X509_V_OK) {
		pr_err("SSL_get_verify_result() failed (%d)\n", ret);
		goto ssl_err;
	}

	/* 3. Hostname verification? */

	/* not 100% necessary, but might be helpful */
	ret = SSL_get_fd(td->ssl);
	if (ret < 0) {
		pr_err("SSL_get_fd() failed (%d)\n", ret);
		goto ssl_err;
	} else {
		tconn->sock = ret;
	}

	pr_info("Connected to module\n");
	ret = 0;

	goto out;

ssl_err:
	ERR_print_errors_fp(stderr);
	if (ret == 0) {
		ret = -EIO;
	}

	if (td->bio != NULL) {
		BIO_ssl_shutdown(td->bio);
		BIO_free(td->bio);
		td->bio = NULL;
	}

	if (td->ctx != NULL) {
		SSL_CTX_free(td->ctx);
		td->ctx = NULL;
	}

	if (tconn != NULL) {
		free(tconn);
		tconn = NULL;
	}

out:
	if (hostname != NULL) {
		free(hostname);
		hostname = NULL;
	}

	return ret;
}

static int tls_connection_destroy(struct connection *conn)
{
	struct tls_connection *tconn = conn->priv;
	struct tls_device *td = conn->intf2->priv;

	conn->priv = NULL;
	pr_info("closing socket %d\n", tconn->sock);

	if (td->bio != NULL) {
		BIO_ssl_shutdown(td->bio);
		BIO_free(td->bio);
		td->bio = NULL;
	}

	if (td->ctx != NULL) {
		SSL_CTX_free(td->ctx);
		td->ctx = NULL;
	}

	td->ssl = NULL;
	free(tconn);

	return 0;
}

static void tls_hotplug(struct controller *ctrl, const char *host_name,
			  const AvahiAddress *address, uint16_t port)
{
	struct interface *intf;
	struct tls_device *td;

	td = calloc(1, sizeof(*td));
	if (!td)
		goto exit;

	td->port = port;
	avahi_address_snprint(td->addr, sizeof(td->addr), address);
	td->host_name = malloc(strlen(host_name) + 1);
	if (!td->host_name)
		goto err_free_td;

	strcpy(td->host_name, host_name);

	switch(address->proto) {
	case AVAHI_PROTO_INET:
		td->family = AF_INET;
		break;
	case AVAHI_PROTO_INET6:
		td->family = AF_INET6;
		break;
	default:
		goto err_free_host_name;
	}

	/* FIXME: use real IDs */
	intf = interface_create(ctrl, 1, 1, 0x1234, td);
	if (!intf)
		goto err_free_host_name;

	if (interface_hotplug(intf))
		goto err_intf_destroy;

	return;

err_intf_destroy:
	interface_destroy(intf);
err_free_host_name:
	free(td->host_name);
err_free_td:
	free(td);
exit:
	pr_err("Failed to hotplug of TLS module\n");
}

static void resolve_callback(AvahiServiceResolver *r,
				 AvahiIfIndex interface,
				 AvahiProtocol protocol,
				 AvahiResolverEvent event,
				 const char *name,
				 const char *type,
				 const char *domain,
				 const char *host_name,
				 const AvahiAddress *address,
				 uint16_t port,
				 AvahiStringList *txt,
				 AvahiLookupResultFlags flags,
				 void* userdata)
{
	AvahiClient *c;
	struct controller *ctrl = userdata;

	switch (event) {
	case AVAHI_RESOLVER_FAILURE:
		c = avahi_service_resolver_get_client(r);
		pr_err("(Resolver) Failed to resolve service"
			" '%s' of type '%s' in domain '%s': %s\n",
			name, type, domain,
			avahi_strerror(avahi_client_errno(c)));
		break;

	case AVAHI_RESOLVER_FOUND:
		tls_hotplug(ctrl, host_name, address, port);
		break;
	}

	avahi_service_resolver_free(r);
}

static void browse_callback(AvahiServiceBrowser *b,
				AvahiIfIndex interface,
				AvahiProtocol protocol,
				AvahiBrowserEvent event,
				const char *name,
				const char *type,
				const char *domain,
				AvahiLookupResultFlags flags,
				void* userdata)
{
	struct controller *ctrl = userdata;
	struct tls_controller *tls_ctrl = ctrl->priv;
	AvahiClient *c = tls_ctrl->client;
	AvahiServiceResolver *r;

	switch (event) {
	case AVAHI_BROWSER_FAILURE:
		c = avahi_service_browser_get_client(b);
		pr_err("(Browser) %s\n", 
			avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(tls_ctrl->simple_poll);
		return;

	case AVAHI_BROWSER_NEW:
		r = avahi_service_resolver_new(c, interface, protocol,
						   name, type, domain,
						   AVAHI_PROTO_UNSPEC, 0,
						   resolve_callback, userdata);
		if (!r) {
			pr_err("Failed to resolve service '%s': %s\n",
				name, avahi_strerror(avahi_client_errno(c)));
		}

		return;

	case AVAHI_BROWSER_REMOVE:
		/* TODO */
		return;

	default:
		return;
	}
}

static void client_callback(AvahiClient *c,
				AvahiClientState state, void *userdata)
{
	struct controller *ctrl = userdata;
	struct tls_controller *tls_ctrl = ctrl->priv;

	if (state == AVAHI_CLIENT_FAILURE) {
		pr_err("Server connection failure: %s\n",
			avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(tls_ctrl->simple_poll);
	}
}

static void tls_intf_destroy(struct interface *intf)
{
}

static int avahi_discovery(struct controller *ctrl)
{
	AvahiClient *client;
	AvahiServiceBrowser *sb;
	AvahiSimplePoll *simple_poll;
	struct tls_controller *tls_ctrl = ctrl->priv;
	int ret = 0;
	int error;

	simple_poll = avahi_simple_poll_new();
	if (!simple_poll) {
		pr_err("Failed to create simple poll object\n");
		return -ENOMEM;
	}

	client = avahi_client_new(avahi_simple_poll_get(simple_poll),
				  0, client_callback, ctrl, &error);
	if (!client) {
		ret = error;
		pr_err("Failed to create client: %s\n", avahi_strerror(error));
		goto err_simple_pool_free;
	}

	tls_ctrl->client = client;
	sb = avahi_service_browser_new(client,
					   AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
					   /* 's' suffix for TLS version of greybus */
					   "_greybuss._tcp", NULL, 0,
					   browse_callback, ctrl); 
	if (!sb) {
		ret = avahi_client_errno(client);
		pr_err("Failed to create service browser: %s\n",
			avahi_strerror(avahi_client_errno(client)));
		goto err_client_free;
	}

	tls_ctrl->simple_poll = simple_poll;
	avahi_simple_poll_loop(simple_poll);

	avahi_service_browser_free(sb);
err_client_free:
	avahi_client_free(client);
err_simple_pool_free:
	avahi_simple_poll_free(simple_poll);

	return ret;
}

static void avahi_discovery_stop(struct controller *ctrl)
{
	struct tls_controller *tls_ctrl = ctrl->priv;
	avahi_simple_poll_quit(tls_ctrl->simple_poll);
}

static int tls_write(struct connection *conn, void *data, size_t len)
{
	struct tls_device *td = conn->intf2->priv;

	return BIO_write(td->bio, data, len);
}

static int _tls_read(BIO *bio, void *data, size_t len)
{
	int ret;
	size_t remaining;
	size_t offset;
	size_t recvd;

	if (0 == len) {
		return 0;
	}

	for(remaining = len, offset = 0, recvd = 0; remaining; remaining -= recvd, offset += recvd, recvd = 0) {
		ret = BIO_read(bio, &((uint8_t *)data)[offset], remaining);
		if (ret <= 0) {
			pr_err("BIO_read() failed (%d)\n", ret);
			return ret;
		}
		recvd = ret;
	}

	return 0;
}

static int tls_read(struct connection *conn, void *data, size_t len)
{
	struct tls_device *td = conn->intf2->priv;

	int ret;
	uint8_t *p_data = data;
	size_t msg_size;
	size_t payload_size;

	ret = _tls_read(td->bio, p_data, sizeof(struct gb_operation_msg_hdr));
	if (ret) {
		pr_err("Failed to get header\n");
		return ret;
	}

	msg_size = gb_operation_msg_size(data);
	payload_size = msg_size - sizeof(struct gb_operation_msg_hdr);
	p_data += sizeof(struct gb_operation_msg_hdr);

	ret = _tls_read(td->bio, p_data, payload_size);
	if (ret < 0) {
		pr_err("Failed to get payload\n");
		return ret;
	}

	return msg_size;
}

static int tls_init(struct controller *ctrl)
{
	struct tls_controller *tls_ctrl;

	tls_ctrl = malloc(sizeof(*tls_ctrl));
	if (!tls_ctrl)
		return -ENOMEM;
	 ctrl->priv = tls_ctrl;

	return 0;
}

static void tls_exit(struct controller *ctrl)
{
	free(ctrl->priv);
}


struct controller tls_controller = {
	.name = "TLS",
	.init = tls_init,
	.exit = tls_exit,
	.connection_create = tls_connection_create,
	.connection_destroy = tls_connection_destroy,
	.event_loop = avahi_discovery,
	.event_loop_stop = avahi_discovery_stop,
	.write = tls_write,
	.read = tls_read,
	.interface_destroy = tls_intf_destroy,
};
