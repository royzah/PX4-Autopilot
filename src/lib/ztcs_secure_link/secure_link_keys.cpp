/****************************************************************************
 * Key material for the link, from the PX4 keystore.
 *
 * The static private key is generated here and never leaves: a key that has
 * no existence off the aircraft cannot leak from a laptop, a build log or a
 * backup. Only the public half is ever read out, for enrolment to sign.
 *
 * Separate from secure_link.c, and C++, because the keystore API is PX4's
 * and the state machine must stay portable C that a non-PX4 NuttX target
 * can build. The state machine never learns where its keys came from.
 ****************************************************************************/

#include "secure_link.h"

#include <px4_platform_common/log.h>

#include <string.h>

/* The keystore and its backend headers exist only when the board opted into
 * a crypto implementation. Without one there is nowhere to keep a private
 * key, so the link stays closed rather than inventing a home for it.
 */
#if defined(PX4_CRYPTO)

#include <px4_platform_common/crypto_backend.h>

/* Slot 8 is written by this code on first boot. Slots 9 and 10 are written
 * by enrolment, which cannot happen until slot 8 exists: the identity
 * payload is a signature over the public half of slot 8.
 */
#ifndef ZTCS_KEY_SLOT_STATIC_PRIVATE
#define ZTCS_KEY_SLOT_STATIC_PRIVATE 8
#endif
#ifndef ZTCS_KEY_SLOT_STATION_PUBLIC
#define ZTCS_KEY_SLOT_STATION_PUBLIC 9
#endif
#ifndef ZTCS_KEY_SLOT_IDENTITY
#define ZTCS_KEY_SLOT_IDENTITY 10
#endif

static bool read_slot(keystore_session_handle_t ks, uint8_t idx,
		      uint8_t *out, size_t expect)
{
	/* A short read leaves the tail of the buffer as whatever was there,
	 * which for a key means a weak one rather than a loud failure.
	 */
	return keystore_get_key(ks, idx, out, expect) == expect;
}

static bool all_zero(const uint8_t *b, size_t len)
{
	uint8_t acc = 0;

	for (size_t i = 0; i < len; i++) {
		acc |= b[i];
	}

	return acc == 0;
}

/****************************************************************************
 * Name: draw_static_key
 *
 * Description:
 *   Draw a static private key, refusing anything an unseeded pool would
 *   produce. On a board whose entropy is not yet wired, /dev/random hands
 *   back zeros or the same bytes every time, and both look like a key. Two
 *   independent draws that agree, or either being zero, means the pool is
 *   not a source and no key is written.
 *
 *   Refusing is the whole point. A device that cannot make a good key must
 *   not make a bad one: the bad one works, and nothing downstream can tell.
 *
 ****************************************************************************/

static bool draw_static_key(uint8_t out[NOISE_DHLEN])
{
	uint8_t probe[NOISE_DHLEN];

	if (noise_random(out, NOISE_DHLEN) != 0
	    || noise_random(probe, NOISE_DHLEN) != 0) {
		PX4_ERR("no entropy source; refusing to generate a key");
		return false;
	}

	if (all_zero(out, NOISE_DHLEN) || all_zero(probe, NOISE_DHLEN)
	    || memcmp(out, probe, NOISE_DHLEN) == 0) {
		PX4_ERR("entropy pool is not seeded; refusing to generate a key");
		memset(out, 0, NOISE_DHLEN);
		memset(probe, 0, sizeof(probe));
		return false;
	}

	memset(probe, 0, sizeof(probe));
	return true;
}

bool secure_link_ensure_keys(struct secure_link_keys *keys)
{
	/* The handle type comes from the board's crypto backend, so there is no
	 * portable way to test it here. A failed open surfaces as a short read.
	 */
	keystore_session_handle_t ks = keystore_open();
	bool ok = false;

	if (!read_slot(ks, ZTCS_KEY_SLOT_STATIC_PRIVATE, keys->static_private, NOISE_DHLEN)) {
		PX4_INFO("no static key yet; generating one");

		if (draw_static_key(keys->static_private)
		    && keystore_put_key(ks, ZTCS_KEY_SLOT_STATIC_PRIVATE,
					keys->static_private, NOISE_DHLEN)) {
			PX4_INFO("static key generated and stored");

		} else {
			PX4_ERR("could not establish a static key");
			goto out;
		}
	}

	/* Written by enrolment, which needs the public half of the key above,
	 * so on a first boot these are legitimately absent. The link stays
	 * closed until they arrive, which is not an error worth shouting about
	 * twice.
	 */
	if (!read_slot(ks, ZTCS_KEY_SLOT_STATION_PUBLIC, keys->station_public, NOISE_DHLEN)
	    || !read_slot(ks, ZTCS_KEY_SLOT_IDENTITY, keys->identity,
			  NOISE_IDENTITY_PAYLOAD_LEN)) {
		PX4_WARN("not enrolled yet: no station key or identity");
		goto out;
	}

	ok = true;

out:
	keystore_close(&ks);

	if (!ok) {
		/* A partially loaded key set is worse than none, because it
		 * still looks like keys.
		 */
		memset(keys, 0, sizeof(*keys));
	}

	return ok;
}

bool secure_link_public_key(uint8_t out[NOISE_DHLEN])
{
	keystore_session_handle_t ks = keystore_open();
	uint8_t priv[NOISE_DHLEN];
	bool ok = read_slot(ks, ZTCS_KEY_SLOT_STATIC_PRIVATE, priv, NOISE_DHLEN);

	keystore_close(&ks);

	if (ok) {
		noise_dh_public(priv, out);
	}

	memset(priv, 0, sizeof(priv));
	return ok;
}

#else /* PX4_CRYPTO */

bool secure_link_ensure_keys(struct secure_link_keys *keys)
{
	memset(keys, 0, sizeof(*keys));
	PX4_ERR("no keystore on this board: enable the PX4 crypto backend");
	return false;
}

bool secure_link_public_key(uint8_t out[NOISE_DHLEN])
{
	memset(out, 0, NOISE_DHLEN);
	return false;
}

#endif /* PX4_CRYPTO */
