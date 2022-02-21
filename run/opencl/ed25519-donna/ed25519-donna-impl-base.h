/*
	conversions
*/

static void
ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t);
}

static void
ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t);
	curve25519_mul(r->t, p->x, p->y);
}

/*
	adding & doubling
*/

static void
ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p) {
	bignum25519 a,b,c;

	curve25519_square(a, p->x);
	curve25519_square(b, p->y);
	curve25519_square(c, p->z);
	curve25519_add_reduce(c, c, c);
	curve25519_add(r->x, p->x, p->y);
	curve25519_square(r->x, r->x);
	curve25519_add(r->y, b, a);
	curve25519_sub(r->z, b, a);
	curve25519_sub_after_basic(r->x, r->x, r->y);
	curve25519_sub_after_basic(r->t, c, r->z);
}

static void
ge25519_double_partial(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_partial(r, &t);
}

static void
ge25519_double(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q) {
	bignum25519 a,b,c,e,f,g,h;

	curve25519_sub(a, r->y, r->x);
	curve25519_add(b, r->y, r->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(e, b, q->xaddy);
	curve25519_add(h, e, a);
	curve25519_sub(e, e, a);
	curve25519_mul(c, r->t, q->t2d);
	curve25519_add(f, r->z, r->z);
	curve25519_add_after_basic(g, f, c);
	curve25519_sub_after_basic(f, f, c);
	curve25519_mul(r->x, e, f);
	curve25519_mul(r->y, h, g);
	curve25519_mul(r->z, g, f);
	curve25519_mul(r->t, e, h);
}

/*
	pack & unpack
*/

static void
ge25519_pack(unsigned char r[32], const ge25519 *p) {
	bignum25519 tx, ty, zi;
	unsigned char parity[32];
	curve25519_recip(zi, p->z);
	curve25519_mul(tx, p->x, zi);
	curve25519_mul(ty, p->y, zi);
	curve25519_contract(r, ty);
	curve25519_contract(parity, tx);
	r[31] ^= ((parity[0] & 1) << 7);
}

static uint32_t
ge25519_windowb_equal(uint32_t b, uint32_t c) {
	return ((b ^ c) - 1) >> 31;
}

static void
ge25519_scalarmult_base_choose_niels(ge25519_niels *t, uint32_t pos, signed char b) {
	bignum25519 neg;
	uint32_t sign = (uint32_t)((unsigned char)b >> 7);
	uint32_t mask = ~(sign - 1);
	uint32_t u = (b + mask) ^ mask;
	uint32_t i;

	/* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
	uint8_t packed[96] = {0};
	packed[0] = 1;
	packed[32] = 1;

	for (i = 0; i < 8; i++)
		curve25519_move_conditional_bytes(packed, ge25519_niels_base_multiples[(pos * 8) + i], ge25519_windowb_equal(u, i + 1));

	/* expand in to t */
	curve25519_expand(t->ysubx, packed +  0);
	curve25519_expand(t->xaddy, packed + 32);
	curve25519_expand(t->t2d  , packed + 64);

	/* adjust for sign */
	curve25519_swap_conditional(t->ysubx, t->xaddy, sign);
	curve25519_neg(neg, t->t2d);
	curve25519_swap_conditional(t->t2d, neg, sign);
}

/* computes [s]basepoint */
static void
ge25519_scalarmult_base_niels(ge25519 *r, const bignum256modm s) {
	signed char b[64];
	uint32_t i;
	ge25519_niels t;

	contract256_window4_modm(b, s);

	ge25519_scalarmult_base_choose_niels(&t, 0, b[1]);
	curve25519_sub_reduce(r->x, t.xaddy, t.ysubx);
	curve25519_add_reduce(r->y, t.xaddy, t.ysubx);
	memset_p(r->z, 0, sizeof(bignum25519));
	curve25519_copy(r->t, t.t2d);
	r->z[0] = 2;
	for (i = 3; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double(r, r);
	ge25519_scalarmult_base_choose_niels(&t, 0, b[0]);
	curve25519_mul_const(t.t2d, t.t2d, ge25519_ecd);
	ge25519_nielsadd2(r, &t);
	for(i = 2; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
}
