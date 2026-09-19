/****************************************************************************
 * Loads the link's key material from the PX4 keystore.
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

/* Keystore slots, provisioned off-board. The identity payload is minted by
 * signing the Noise static public key with the aircraft identity key, which
 * this side never holds: it carries the signature, not the power to make
 * another one.
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

static bool load_slot(keystore_session_handle_t ks, uint8_t idx,
		      uint8_t *out, size_t expect)
{
	size_t got = keystore_get_key(ks, idx, out, expect);

	/* A short read leaves the tail of the buffer as whatever was there,
	 * which for a key means a weak one rather than a loud failure.
	 */
	if (got != expect) {
		PX4_ERR("keystore slot %u is %zu bytes, expected %zu", idx, got, expect);
		return false;
	}

	return true;
}

bool secure_link_load_keys(struct secure_link_keys *keys)
{
	/* The handle type comes from the board's crypto backend, so there is no
	 * portable way to test it here. A failed open surfaces as a short read
	 * below, which is checked.
	 */
	keystore_session_handle_t ks = keystore_open();

	bool ok = load_slot(ks, ZTCS_KEY_SLOT_STATIC_PRIVATE, keys->static_private, NOISE_DHLEN)
		  && load_slot(ks, ZTCS_KEY_SLOT_STATION_PUBLIC, keys->station_public, NOISE_DHLEN)
		  && load_slot(ks, ZTCS_KEY_SLOT_IDENTITY, keys->identity, NOISE_IDENTITY_PAYLOAD_LEN);

	keystore_close(&ks);

	if (!ok) {
		/* Leave nothing usable behind: a partially loaded key set is
		 * more dangerous than none, because it still looks like keys.
		 */
		memset(keys, 0, sizeof(*keys));
		return false;
	}

	return true;
}

#else /* PX4_CRYPTO */

bool secure_link_load_keys(struct secure_link_keys *keys)
{
	memset(keys, 0, sizeof(*keys));
	PX4_ERR("no keystore on this board: enable the PX4 crypto backend");
	return false;
}

#endif /* PX4_CRYPTO */
