/****************************************************************************
 * Secure MAVLink link, aircraft side.
 *
 * Terminates Noise_IK_25519_ChaChaPoly_SHA256 against the ground station.
 * The wire contract is docs/rfc-secure-mavlink.md in the ZTCS repository;
 * the ground station is ztcs-mavlink-gateway and the two are tested against
 * each other.
 *
 * Sans-io, like the Rust side: this owns no socket and no timer. The caller
 * passes the clock in and sends the datagrams handed back. That is what
 * makes the state machine testable on a host, where a flight controller's
 * timing cannot be reproduced.
 *
 * MAVLink is never parsed. It is an opaque payload.
 ****************************************************************************/

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "noise/noise_ik.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Largest datagram either direction, sized for a MAVLink v2 frame plus the
 * 25 bytes of transport overhead, rounded up.
 */
#define SECURE_LINK_MTU 512

/* Handshake retransmit. A lost message 1 is a dead session with nothing
 * underneath to recover it, so this is ours to drive. Exponential with
 * jitter up to the cap, then a slow retry rather than spinning.
 */
#define SECURE_LINK_RETRY_MIN_US     100000ULL   /* 100 ms */
#define SECURE_LINK_RETRY_CAP_US    2000000ULL   /* 2 s */
#define SECURE_LINK_RETRY_SLOW_US   5000000ULL   /* 5 s once backed off */

/* Rekey triggers, which are separate causes and not one condition. */
#define SECURE_LINK_SILENCE_US     10000000ULL   /* nothing opened in 10 s */
#define SECURE_LINK_DECRYPT_FAILS        16      /* peer restarted, likely */

enum secure_link_state {
  SECURE_LINK_DOWN = 0,   /* no keys */
  SECURE_LINK_HANDSHAKING,
  SECURE_LINK_ESTABLISHED,
};

/* Provisioned material. The identity payload is minted once, off-board, by
 * signing the Noise static public key with the aircraft identity key; this
 * side never holds the identity private key.
 */
struct secure_link_keys {
  uint8_t static_private[NOISE_DHLEN];
  uint8_t station_public[NOISE_DHLEN];
  uint8_t identity[NOISE_IDENTITY_PAYLOAD_LEN];
};

struct secure_link {
  enum secure_link_state state;
  struct secure_link_keys keys;
  struct noise_initiator ini;
  struct noise_session session;

  uint64_t next_retry_us;
  uint64_t retry_interval_us;
  uint64_t last_open_us;   /* last frame that passed the AEAD */
  uint32_t decrypt_fails;

  /* Kept for the log, since a link that rekeys often is a symptom. */
  uint32_t handshakes;
};

/* Loads keys and arms the first handshake. Returns 0, or a negative
 * NOISE_ERR_* value.
 */
int secure_link_init(struct secure_link *sl,
                     const struct secure_link_keys *keys, uint64_t now_us);

/* Datagram due to be sent now, or 0 if nothing is. This is where handshake
 * retransmit and the silence trigger live, so it must be called regularly
 * whether or not there is traffic.
 */
int secure_link_poll(struct secure_link *sl, uint64_t now_us,
                     uint8_t *out, size_t cap);

/* Seals application bytes. Negative when there is no session to seal under,
 * which the caller should treat as "drop", not as an error to retry.
 */
int secure_link_seal(struct secure_link *sl, uint64_t now_us,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *out, size_t cap);

/* Handles an inbound datagram. Returns the plaintext length, 0 when the
 * datagram was protocol and has been consumed, negative when it was
 * rejected. A rejected datagram is not an error the caller can act on: the
 * rekey triggers deal with a peer that has moved on.
 */
int secure_link_open(struct secure_link *sl, uint64_t now_us,
                     const uint8_t *frame, size_t len,
                     uint8_t *out, size_t cap);

static inline bool secure_link_is_up(const struct secure_link *sl)
{
  return sl->state == SECURE_LINK_ESTABLISHED;
}

#ifdef __cplusplus
}
#endif
