#ifndef ETHERNET_CSUM_H
#define ETHERNET_CSUM_H

/* Offload-partial transport checksums, repaired at the point a real wire would
   have carried them filled in.

   A sender, or a host bridge resegmenting a GRO'd train, that hands its NIC a
   CHECKSUM_PARTIAL packet stores only the pseudo-header sum in the transport
   checksum field and leaves the rest to hardware.  libpcap taps the frame
   before that hardware step, so on a virtualised path the emulated guest
   receives byte streams no real NIC would ever put on a wire: valid data,
   checksum field holding exactly the pseudo-header sum.  A verifying guest
   stack then drops every such segment and the sender's RTO becomes the
   transfer's clock.  QEMU's net layer performs the same fix-up for emulated
   NICs that do not do offload; this is the pcap-backend equivalent.

   Only a frame whose stored checksum equals the pseudo-header sum, or its
   complement, is touched, so a genuinely corrupt frame still reaches the guest
   exactly as it arrived.

   IPv4 and IPv6 both, TCP/UDP over either and ICMPv6, whose checksum covers a
   pseudo-header the way ICMPv4's does not.

   Header rather than a .cpp so tests/ethernet_csum_test.cpp can exercise the
   parsing and the gate without the emulator around it. */

#include <cstdint>

static inline uint32_t ethernet_csum_add(uint32_t sum, const uint8_t *p, int len)
{
	for (int i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (len & 1)
		sum += p[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

/* Offset of the checksum field within the transport header, or -1 for a
   protocol whose checksum is not over a pseudo-header (ICMPv4) or that we
   cannot complete from one frame (fragments, ESP). */
static inline int ethernet_csum_offset(int proto, bool v6)
{
	switch (proto) {
	case 6:
		return 16;				/* TCP */
	case 17:
		return 6;				/* UDP */
	case 58:
		return v6 ? 2 : -1;			/* ICMPv6 */
	}
	return -1;
}

/* pseudo is the folded pseudo-header sum, trlen the upper-layer length it
   covers.  The frame is rewritten only if the stored field still holds that
   sum, which is what a CHECKSUM_PARTIAL sender left there; anything else is
   either already complete or genuinely damaged, and is passed through. */
static inline bool ethernet_repair_csum(uint8_t *tr, int trlen, int csum_off, uint32_t pseudo, bool udp)
{
	const uint32_t stored = (tr[csum_off] << 8) | tr[csum_off + 1];
	if (stored != pseudo && stored != ((~pseudo) & 0xffff))
		return false;
	tr[csum_off] = 0;
	tr[csum_off + 1] = 0;
	uint32_t sum = ethernet_csum_add(pseudo, tr, trlen);
	sum = (~sum) & 0xffff;
	if (udp && sum == 0)
		sum = 0xffff;
	tr[csum_off] = (uint8_t)(sum >> 8);
	tr[csum_off + 1] = (uint8_t)(sum & 0xff);
	return true;
}

/* Walk the IPv6 extension header chain to the transport header.  Returns its
   offset from the start of the IPv6 header and stores the last Next Header
   value, which is the protocol number the pseudo-header carries, or -1 if the
   chain runs off the end of the frame or nests absurdly. */
static inline int ethernet_ipv6_transport(const uint8_t *ip, int totlen, int *proto)
{
	int off = 40;
	int nh = ip[6];
	for (int hops = 0; hops < 8; hops++) {
		int hlen;
		switch (nh) {
		case 0:					/* hop-by-hop options */
		case 43:				/* routing */
		case 60:				/* destination options */
		case 135:				/* mobility */
		case 139:				/* host identity protocol */
		case 140:				/* shim6 */
			if (off + 8 > totlen)
				return -1;
			hlen = (ip[off + 1] + 1) * 8;
			break;
		case 51:				/* authentication, 4-octet units */
			if (off + 8 > totlen)
				return -1;
			hlen = (ip[off + 1] + 2) * 4;
			break;
		default:
			*proto = nh;
			return off;
		}
		nh = ip[off];
		off += hlen;
		if (off > totlen)
			return -1;
	}
	return -1;
}

/* True if the frame was rewritten. */
static inline bool ethernet_csum_fix_frame(uint8_t *d, int len)
{
	if (len < 14 + 20)
		return false;
	const int ethertype = (d[12] << 8) | d[13];
	uint8_t *ip = d + 14;
	uint32_t pseudo;
	int proto, troff, trlen;

	if (ethertype == 0x0800) {
		const int ihl = (ip[0] & 0x0f) * 4;
		const int totlen = (ip[2] << 8) | ip[3];
		if ((ip[0] >> 4) != 4 || ihl < 20 || totlen < ihl || totlen > len - 14)
			return false;
		if (((ip[6] & 0x3f) | ip[7]) != 0)	/* no fragments */
			return false;
		proto = ip[9];
		troff = ihl;
		trlen = totlen - ihl;
		pseudo = ethernet_csum_add(0, ip + 12, 8);	/* src, dst */
		pseudo += proto + trlen;
	} else if (ethertype == 0x86dd) {
		if (len < 14 + 40)
			return false;
		const int paylen = (ip[4] << 8) | ip[5];
		const int totlen = 40 + paylen;
		if ((ip[0] >> 4) != 6 || paylen == 0 || totlen > len - 14)
			return false;			/* jumbogram or truncated */
		troff = ethernet_ipv6_transport(ip, totlen, &proto);
		if (troff < 0)
			return false;
		trlen = totlen - troff;
		/* 16 bytes each of source and destination, a 32-bit upper-layer
		   length and the next header in the low byte of a 32-bit field;
		   trlen cannot exceed 16 bits, so both fold in as one addend. */
		pseudo = ethernet_csum_add(0, ip + 8, 32);
		pseudo += proto + trlen;
	} else {
		return false;
	}

	const int csum_off = ethernet_csum_offset(proto, ethertype == 0x86dd);
	if (csum_off < 0 || trlen < csum_off + 2)
		return false;
	while (pseudo >> 16)
		pseudo = (pseudo & 0xffff) + (pseudo >> 16);
	return ethernet_repair_csum(ip + troff, trlen, csum_off, pseudo, proto == 17);
}

#endif /* ETHERNET_CSUM_H */
