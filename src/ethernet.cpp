
#include "sysconfig.h"
#include "sysdeps.h"

#include "ethernet.h"
#if defined(WITH_UAENET_PCAP) || defined(WITH_UAENET_TAP)
#define HAVE_UAENET_BACKEND
#include "uaenet.h"
#endif
#include "threaddep/thread.h"
#include "options.h"
#include "sana2.h"
#include "uae/slirp.h"
#include "gui.h"
#include "rommgr.h"

#ifdef _WIN32
/* Need struct in_addr and inet_addr for SLIRP IP configuration. */
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#ifndef HAVE_INET_ATON
static int inet_aton(const char *cp, struct in_addr *ia)
{
	uint32_t addr = inet_addr(cp);
	if (addr == 0xffffffff)
		return 0;
	ia->s_addr = addr;
	return 1;
}
#endif

struct ethernet_data
{
	ethernet_gotfunc *gotfunc;
	ethernet_getfunc *getfunc;
	void *userdata;
};

#define SLIRP_PORT_OFFSET 0

static const int slirp_ports[] = { 21, 22, 23, 80, 0 };

static struct ethernet_data *slirp_data;
static bool slirp_inited;
uae_sem_t slirp_sem1, slirp_sem2;
static int netmode;

static struct netdriverdata slirpd =
{
	UAENET_SLIRP,
	_T("slirp"), _T("SLIRP User Mode NAT"),
	1500,
	{ 0x00, 0x00, 0x00, 50, 51, 52 },
	{ 0x00, 0x00, 0x00, 50, 51, 52 },
	1
};
static struct netdriverdata slirpd2 =
{
	UAENET_SLIRP_INBOUND,
	_T("slirp_inbound"), _T("SLIRP + Open ports (21-23,80)"),
	1500,
	{ 0x00, 0x00, 0x00, 50, 51, 52 },
	{ 0x00, 0x00, 0x00, 50, 51, 52 },
	1
};

void slirp_output (const uint8_t *pkt, int pkt_len)
{
	if (!slirp_data)
		return;
	gui_flicker_led(LED_NET, 0, gui_data.net | 1);
	uae_sem_wait (&slirp_sem1);
	slirp_data->gotfunc (slirp_data->userdata, pkt, pkt_len);
	uae_sem_post (&slirp_sem1);
}

void ethernet_trigger (struct netdriverdata *ndd, void *vsd)
{
	if (!ndd)
		return;
	gui_flicker_led(LED_NET, 0, gui_data.net | 2);
	switch (ndd->type)
	{
#ifdef WITH_SLIRP
		case UAENET_SLIRP:
		case UAENET_SLIRP_INBOUND:
		{
			struct ethernet_data *ed = (struct ethernet_data*)vsd;
			if (slirp_data) {
				uae_u8 pkt[4000];
				int len = sizeof pkt;
				int v;
				uae_sem_wait (&slirp_sem1);
				v = slirp_data->getfunc(ed->userdata, pkt, &len);
				uae_sem_post (&slirp_sem1);
				if (v) {
					uae_sem_wait (&slirp_sem2);
					uae_slirp_input(pkt, len);
					uae_sem_post (&slirp_sem2);
				}
			}
		}
		return;
#endif
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		uaenet_trigger (vsd);
		return;
#endif
	}
}

void ethernet_receive_poll (struct netdriverdata *ndd, void *vsd)
{
	if (!ndd)
		return;
	switch (ndd->type)
	{
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		uaenet_receive_poll (vsd);
		return;
#endif
	}
}

/* Offload-partial transport checksums, repaired at the point a real wire would
   have carried them filled in.

   A sender, or a host bridge resegmenting a GRO'd train, that hands its NIC a
   CHECKSUM_PARTIAL packet stores only the pseudo-header sum in the TCP/UDP
   checksum field and leaves the rest to hardware.  libpcap taps the frame
   before that hardware step, so on a virtualised path the emulated guest
   receives byte streams no real NIC would ever put on a wire: valid data,
   checksum field holding exactly the pseudo-header sum.  A verifying guest
   stack then drops every such segment and the sender's RTO becomes the
   transfer's clock.  QEMU's net layer performs the same fix-up for emulated
   NICs that do not do offload; this is the pcap-backend equivalent.

   Only a frame whose stored checksum equals the pseudo-header sum, or its
   complement, is touched, so a genuinely corrupt frame still reaches the guest
   exactly as it arrived.  AMIBERRY_NET_CSUM_FIX=0 disables.

   Called from each NIC's receive path on that NIC's own copy of the frame, not
   from the capture thread: the pcap buffer is const and shared. */

static uae_u32 ethernet_csum_add(uae_u32 sum, const uae_u8 *p, int len)
{
	for (int i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (len & 1)
		sum += p[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static unsigned long ethernet_csum_fixed;

void ethernet_fix_partial_csum(uae_u8 *d, int len)
{
	static int on = -1;
	if (on < 0) {
		const char *e = getenv("AMIBERRY_NET_CSUM_FIX");
		on = (e && !atoi(e)) ? 0 : 1;
	}
	if (!on || len < 14 + 20)
		return;
	if (d[12] != 0x08 || d[13] != 0x00)		/* IPv4 only */
		return;
	uae_u8 *ip = d + 14;
	const int ihl = (ip[0] & 0x0f) * 4;
	const int totlen = (ip[2] << 8) | ip[3];
	if ((ip[0] >> 4) != 4 || ihl < 20 || totlen < ihl || totlen > len - 14)
		return;
	if (((ip[6] & 0x3f) | ip[7]) != 0)		/* no fragments */
		return;
	const int proto = ip[9];
	int csum_off;
	if (proto == 6)
		csum_off = 16;				/* TCP */
	else if (proto == 17)
		csum_off = 6;				/* UDP */
	else
		return;
	uae_u8 *tr = ip + ihl;
	const int trlen = totlen - ihl;
	if (trlen < csum_off + 2)
		return;
	const uae_u32 stored = (tr[csum_off] << 8) | tr[csum_off + 1];
	uae_u32 pseudo = ethernet_csum_add(0, ip + 12, 8);	/* src, dst */
	pseudo += proto + trlen;
	while (pseudo >> 16)
		pseudo = (pseudo & 0xffff) + (pseudo >> 16);
	if (stored != pseudo && stored != ((~pseudo) & 0xffff))
		return;
	tr[csum_off] = 0;
	tr[csum_off + 1] = 0;
	uae_u32 sum = ethernet_csum_add(pseudo, tr, trlen);
	sum = (~sum) & 0xffff;
	if (proto == 17 && sum == 0)
		sum = 0xffff;
	tr[csum_off] = sum >> 8;
	tr[csum_off + 1] = sum & 0xff;
	ethernet_csum_fixed++;
}

int ethernet_open (struct netdriverdata *ndd, void *vsd, void *user, ethernet_gotfunc *gotfunc, ethernet_getfunc *getfunc, int promiscuous, const uae_u8 *mac)
{
	switch (ndd->type)
	{
#ifdef WITH_SLIRP
		case UAENET_SLIRP:
		case UAENET_SLIRP_INBOUND:
		{
			struct ethernet_data *ed = (struct ethernet_data*)vsd;
			ed->gotfunc = gotfunc;
			ed->getfunc = getfunc;
			ed->userdata = user;
			slirp_data = ed;
			uae_sem_init (&slirp_sem1, 0, 1);
			uae_sem_init (&slirp_sem2, 0, 1);
			if (uae_slirp_init() < 0) {
				slirp_data = NULL;
				uae_sem_destroy (&slirp_sem1);
				uae_sem_destroy (&slirp_sem2);
				return 0;
			}
			for (int i = 0; i < MAX_SLIRP_REDIRS; i++) {
				struct slirp_redir *sr = &currprefs.slirp_redirs[i];
				if (sr->proto) {
					struct in_addr a;
					if (sr->srcport == 0) {
					    inet_aton("10.0.2.15", &a);
						uae_slirp_redir (0, sr->dstport, a, sr->dstport);
					} else {
#ifdef HAVE_STRUCT_IN_ADDR_S_UN
						a.S_un.S_addr = sr->addr;
#else
						a.s_addr = sr->addr;
#endif
						uae_slirp_redir (sr->proto == 1 ? 0 : 1, sr->dstport, a, sr->srcport);
					}
				}
			}
			if (ndd->type == UAENET_SLIRP_INBOUND) {
				struct in_addr a;
			    inet_aton("10.0.2.15", &a);
				for (int i = 0; slirp_ports[i]; i++) {
					int port = slirp_ports[i];
					int j;
					for (j = 0; j < MAX_SLIRP_REDIRS; j++) {
						struct slirp_redir *sr = &currprefs.slirp_redirs[j];
						if (sr->proto && sr->dstport == port)
							break;
					}
					if (j == MAX_SLIRP_REDIRS)
						uae_slirp_redir (0, port + SLIRP_PORT_OFFSET, a, port);
				}
			}
			netmode = ndd->type;
			if (!uae_slirp_start ()) {
				uae_slirp_cleanup ();
				slirp_data = NULL;
				uae_sem_destroy (&slirp_sem1);
				uae_sem_destroy (&slirp_sem2);
				return 0;
			}
		}
		return 1;
#endif
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		if (uaenet_open (vsd, ndd, user, gotfunc, getfunc, promiscuous, mac)) {
			netmode = ndd->type;
			return 1;
		}
		return 0;
#endif
	}
	return 0;
}

void ethernet_close (struct netdriverdata *ndd, void *vsd)
{
	if (!ndd)
		return;
	switch (ndd->type)
	{
#ifdef WITH_SLIRP
		case UAENET_SLIRP:
		case UAENET_SLIRP_INBOUND:
		if (slirp_data) {
			uae_slirp_end ();
			uae_slirp_cleanup ();
			slirp_data = NULL;
			uae_sem_destroy (&slirp_sem1);
			uae_sem_destroy (&slirp_sem2);
		}
		return;
#endif
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		return uaenet_close (vsd);
#endif
	}
}

void ethernet_enumerate_free (void)
{
#ifdef WITH_UAENET_TAP
	uaenet_tap_enumerate_free ();
#endif
#ifdef WITH_UAENET_PCAP
	uaenet_enumerate_free ();
#endif
}

bool ethernet_enumerate (struct netdriverdata **nddp, int romtype)
{
	int j;
	struct netdriverdata *nd;
	const TCHAR *name = NULL;
	
	if (romtype) {
		struct romconfig *rc = get_device_romconfig(&currprefs, romtype, 0);
		name = ethernet_getselectionname(rc ? rc->device_settings : 0);
	}

	gui_flicker_led(LED_NET, 0, 0);
	if (name) {
		netmode = 0;
		*nddp = NULL;
		if (!_tcsicmp (slirpd.name, name))
			*nddp = &slirpd;
		if (!_tcsicmp (slirpd2.name, name))
			*nddp = &slirpd2;
#ifdef WITH_UAENET_TAP
		if (*nddp == NULL) {
			struct netdriverdata *tapd = uaenet_tap_enumerate (name);
			if (tapd && tapd[0].active)
				*nddp = tapd;
		}
#endif
#ifdef WITH_UAENET_PCAP
		if (*nddp == NULL)
			*nddp = uaenet_enumerate (name);
#endif
		if (*nddp) {
			netmode = (*nddp)->type;
			return true;
		}
		return false;
	}
	j = 0;
	nddp[j++] = &slirpd;
	nddp[j++] = &slirpd2;
#ifdef WITH_UAENET_TAP
	nd = uaenet_tap_enumerate (NULL);
	if (nd) {
		int last = MAX_TOTAL_NET_DEVICES - 1 - j;
		for (int i = 0; i < last; i++) {
			if (nd[i].active)
				nddp[j++] = &nd[i];
		}
	}
#endif
#ifdef WITH_UAENET_PCAP
	nd = uaenet_enumerate (NULL);
	if (nd) {
		int last = MAX_TOTAL_NET_DEVICES - 1 - j;
		for (int i = 0; i < last; i++) {
			if (nd[i].active) {
				// Dedup: skip pcap entries whose name matches a TAP entry
				bool dup = false;
				for (int k = 2; k < j; k++) {
					if (nddp[k] && nddp[k]->name && !_tcsicmp(nddp[k]->name, nd[i].name)) {
						dup = true;
						break;
					}
				}
				if (!dup)
					nddp[j++] = &nd[i];
			}
		}
	}
#endif
	nddp[j] = NULL;
	return true;
}

void ethernet_close_driver (struct netdriverdata *ndd)
{
	switch (ndd->type)
	{
		case UAENET_SLIRP:
		case UAENET_SLIRP_INBOUND:
		return;
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		return uaenet_close_driver (ndd);
#endif
	}
	netmode = 0;
}

int ethernet_getdatalength (struct netdriverdata *ndd)
{
	switch (ndd->type)
	{
		case UAENET_SLIRP:
		case UAENET_SLIRP_INBOUND:
		return sizeof (struct ethernet_data);
#ifdef HAVE_UAENET_BACKEND
#ifdef WITH_UAENET_PCAP
		case UAENET_PCAP:
#endif
#ifdef WITH_UAENET_TAP
		case UAENET_TAP:
#endif
		return uaenet_getdatalength ();
#endif
	}
	return 0;
}

bool ethernet_getmac(uae_u8 *m, const TCHAR *mac)
{
	if (!mac)
		return false;
	if (_tcslen(mac) != 3 * 5 + 2)
		return false;
	for (int i = 0; i < 6; i++) {
		TCHAR *endptr;
		if (mac[0] == 0 || mac[1] == 0)
			return false;
		if (i < 5 && (mac[2] != '.' && mac[2] != ':'))
			return false;
		uae_u8 v = (uae_u8)_tcstol(mac, &endptr, 16);
		mac += 3;
		m[i] = v;
	}
	return true;
}
