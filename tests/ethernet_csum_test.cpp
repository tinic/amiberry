/* The partial-checksum repair, and the gate that keeps it off corrupt frames.
   tests/test_ethernet_csum.sh builds and runs this. */
#include <cstdint>
#include <cstdio>
#include <vector>

#include "ethernet_csum.h"

static int failures;

static void check(const bool ok, const char* name)
{
	printf("%s=%s\n", name, ok ? "pass" : "FAIL");
	if (!ok)
		failures++;
}

/* independent of the code under test: a plain ones-complement sum */
static uint32_t refsum(const uint8_t* p, const int len, const uint32_t seed)
{
	uint32_t sum = seed;
	for (int i = 0; i + 1 < len; i += 2)
		sum += (p[i] << 8) | p[i + 1];
	if (len & 1)
		sum += p[len - 1] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

struct frame
{
	std::vector<uint8_t> b;
	int trans_off = 0;		/* transport header, from the start of the frame */
	int trlen = 0;
	int csum_off = 0;
	uint32_t pseudo = 0;
};

/* exthdrs, when not empty, is the first Next Header value followed by the raw
   extension header bytes */
static frame make_v6(const int proto, const std::vector<uint8_t>& exthdrs,
		     const int paylen_bytes, const int csum_off)
{
	frame f;
	f.b.assign(14 + 40, 0);
	for (int i = 0; i < 6; i++) {
		f.b[i] = 0x02;
		f.b[6 + i] = 0x03;
	}
	f.b[12] = 0x86;
	f.b[13] = 0xdd;
	f.b[14 + 0] = 0x60;
	f.b[14 + 6] = exthdrs.empty() ? (uint8_t)proto : exthdrs[0];
	f.b[14 + 7] = 64;
	for (int i = 0; i < 16; i++) {
		f.b[14 + 8 + i] = (uint8_t)(0x20 + i);
		f.b[14 + 24 + i] = (uint8_t)(0x30 + i);
	}
	if (!exthdrs.empty())
		f.b.insert(f.b.end(), exthdrs.begin() + 1, exthdrs.end());
	f.trans_off = (int)f.b.size();
	for (int i = 0; i < paylen_bytes; i++)
		f.b.push_back((uint8_t)(0x41 + (i % 23)));
	f.trlen = paylen_bytes;
	f.csum_off = csum_off;
	const int paylen = (int)f.b.size() - 14 - 40;
	f.b[14 + 4] = (uint8_t)(paylen >> 8);
	f.b[14 + 5] = (uint8_t)(paylen & 0xff);
	uint32_t p = refsum(f.b.data() + 14 + 8, 32, 0);
	p += (uint32_t)(proto + f.trlen);
	while (p >> 16)
		p = (p & 0xffff) + (p >> 16);
	f.pseudo = p;
	return f;
}

static frame make_v4(const int proto, const int paylen_bytes, const int csum_off)
{
	frame f;
	f.b.assign(14 + 20, 0);
	f.b[12] = 0x08;
	f.b[13] = 0x00;
	f.b[14 + 0] = 0x45;
	f.b[14 + 8] = 64;
	f.b[14 + 9] = (uint8_t)proto;
	for (int i = 0; i < 4; i++) {
		f.b[14 + 12 + i] = (uint8_t)(10 + i);
		f.b[14 + 16 + i] = (uint8_t)(20 + i);
	}
	f.trans_off = 14 + 20;
	for (int i = 0; i < paylen_bytes; i++)
		f.b.push_back((uint8_t)(0x41 + (i % 23)));
	f.trlen = paylen_bytes;
	f.csum_off = csum_off;
	const int totlen = (int)f.b.size() - 14;
	f.b[14 + 2] = (uint8_t)(totlen >> 8);
	f.b[14 + 3] = (uint8_t)(totlen & 0xff);
	uint32_t p = refsum(f.b.data() + 14 + 12, 8, 0);
	p += (uint32_t)(proto + f.trlen);
	while (p >> 16)
		p = (p & 0xffff) + (p >> 16);
	f.pseudo = p;
	return f;
}

/* the checksum field as a CHECKSUM_PARTIAL sender leaves it */
static void set_partial(frame& f)
{
	const uint32_t v = (~f.pseudo) & 0xffff;
	f.b[f.trans_off + f.csum_off] = (uint8_t)(v >> 8);
	f.b[f.trans_off + f.csum_off + 1] = (uint8_t)(v & 0xff);
}

static uint32_t stored_of(const frame& f)
{
	return (uint32_t)((f.b[f.trans_off + f.csum_off] << 8) | f.b[f.trans_off + f.csum_off + 1]);
}

/* what a real NIC would have produced */
static uint32_t correct_of(const frame& f)
{
	std::vector<uint8_t> t(f.b.begin() + f.trans_off, f.b.begin() + f.trans_off + f.trlen);
	t[f.csum_off] = 0;
	t[f.csum_off + 1] = 0;
	return (~refsum(t.data(), f.trlen, f.pseudo)) & 0xffff;
}

static void run(const char* name, frame f, const bool expect_repair)
{
	set_partial(f);
	const uint32_t want = expect_repair ? correct_of(f) : stored_of(f);
	const bool did = ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
	check(did == expect_repair && stored_of(f) == want, name);
}

int main()
{
	run("v6_tcp", make_v6(6, {}, 40, 16), true);
	run("v6_udp", make_v6(17, {}, 32, 6), true);
	{
		frame f = make_v6(58, {}, 24, 2);
		f.b[f.trans_off] = 128;			/* echo request */
		run("v6_icmp6", f, true);
	}
	{	/* hop-by-hop, then destination options, then TCP */
		const std::vector<uint8_t> ext = {
			0,
			60, 0, 1, 4, 0, 0, 0, 0,
			6, 1, 1, 4, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		};
		run("v6_tcp_exthdrs", make_v6(6, ext, 40, 16), true);
	}
	{	/* authentication header: 4-octet units, not 8 */
		const std::vector<uint8_t> ext = {
			51,
			17, 2, 0, 0, 1, 1, 1, 1,
			2, 2, 2, 2, 3, 3, 3, 3,
		};
		run("v6_udp_ah", make_v6(17, ext, 24, 6), true);
	}
	{	/* a fragment's checksum spans the whole datagram */
		const std::vector<uint8_t> ext = { 44, 6, 0, 0, 8, 0, 0, 0, 1 };
		run("v6_fragment_untouched", make_v6(6, ext, 40, 16), false);
	}
	{	/* ESP: nothing to complete */
		const std::vector<uint8_t> ext = { 50, 0, 0, 0, 0, 0, 0, 0, 0 };
		run("v6_esp_untouched", make_v6(6, ext, 40, 16), false);
	}
	{	/* damaged data with a checksum that is not the pseudo sum */
		frame f = make_v6(6, {}, 40, 16);
		set_partial(f);
		f.b[f.trans_off + 20] ^= 0xff;
		f.b[f.trans_off + f.csum_off] ^= 0x55;
		const uint32_t before = stored_of(f);
		const bool did = ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
		check(!did && stored_of(f) == before, "v6_corrupt_untouched");
	}
	{	/* a frame already carrying a complete checksum */
		frame f = make_v6(6, {}, 40, 16);
		set_partial(f);
		ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
		const std::vector<uint8_t> once = f.b;
		const bool again = ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
		check(!again && once == f.b, "v6_idempotent");
	}
	run("v4_tcp", make_v4(6, 40, 16), true);
	run("v4_udp", make_v4(17, 32, 6), true);
	run("v4_icmp_untouched", make_v4(1, 24, 2), false);
	run("v4_proto58_untouched", make_v4(58, 24, 2), false);
	{	/* a payload length longer than the frame */
		frame f = make_v6(6, {}, 40, 16);
		set_partial(f);
		f.b[14 + 4] = 0xff;
		f.b[14 + 5] = 0xff;
		const uint32_t before = stored_of(f);
		const bool did = ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
		check(!did && stored_of(f) == before, "v6_bad_paylen_untouched");
	}
	{	/* an extension header that runs off the end */
		frame f = make_v6(6, {}, 40, 16);
		set_partial(f);
		f.b[14 + 6] = 0;
		f.b[f.trans_off] = 6;
		f.b[f.trans_off + 1] = 0xff;
		const uint32_t before = stored_of(f);
		const bool did = ethernet_csum_fix_frame(f.b.data(), (int)f.b.size());
		check(!did && stored_of(f) == before, "v6_ext_overrun_untouched");
	}
	run("v6_tcp_odd_len", make_v6(6, {}, 41, 16), true);

	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
