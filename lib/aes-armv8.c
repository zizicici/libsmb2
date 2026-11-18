/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2026 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "compat.h"

#include "portable-endian.h"

#include "aes-armv8.h"
#include "aes128ccm.h"

#if !SMB2_ARMV8_AES

int smb2_armv8_available(void)
{
        return 0;
}

#else /* SMB2_ARMV8_AES */

#define SMB2_ARMV8 __attribute__((target("+crypto")))

#if defined(__APPLE__)
/* Crypto extensions are architectural on Apple silicon. */
#elif defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_CRYPTO
#ifdef HWCAP_AES
#define HWCAP_CRYPTO HWCAP_AES
#endif
#endif
#endif

int smb2_armv8_available(void)
{
#if defined(__APPLE__)
        return 1;
#elif defined(__linux__) && defined(HWCAP_CRYPTO)
        /* contexts on several threads ask at once: every one finds the same
         * answer, but the cache still has to be atomic */
        static int known = -1;
        int v = __atomic_load_n(&known, __ATOMIC_RELAXED);

        if (v < 0) {
                v = (getauxval(AT_HWCAP) & HWCAP_CRYPTO) != 0;
                __atomic_store_n(&known, v, __ATOMIC_RELAXED);
        }
        return v;
#else
        return 0;
#endif
}

/* FIPS-197 AES-128 key expansion in plain portable C. */
static const uint8_t armv8_sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
        0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
        0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
        0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
        0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
        0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
        0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
        0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
        0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
        0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
        0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
        0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
        0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
        0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
        0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
        0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
        0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static void armv8_key_schedule(const uint8_t key[16],
                               struct smb2_aes128_keys *keys)
{
        uint8_t *w = &keys->rk[0][0];
        uint8_t rcon = 0x01;
        int i;

        memcpy(w, key, 16);
        for (i = 16; i < 176; i += 4) {
                uint8_t t[4] = { w[i - 4], w[i - 3], w[i - 2], w[i - 1] };

                if ((i & 15) == 0) {
                        uint8_t first = t[0];

                        t[0] = armv8_sbox[t[1]] ^ rcon;
                        t[1] = armv8_sbox[t[2]];
                        t[2] = armv8_sbox[t[3]];
                        t[3] = armv8_sbox[first];
                        rcon = (uint8_t)((rcon << 1) ^
                                         ((rcon & 0x80) ? 0x1b : 0));
                }
                w[i + 0] = w[i - 16] ^ t[0];
                w[i + 1] = w[i - 15] ^ t[1];
                w[i + 2] = w[i - 14] ^ t[2];
                w[i + 3] = w[i - 13] ^ t[3];
        }
}

void smb2_armv8_aes128_expand_key(const uint8_t key[16],
                                  struct smb2_aes128_keys *keys)
{
        armv8_key_schedule(key, keys);
}

/* CCM, mirroring the portable implementation in aes128ccm.c exactly. */

SMB2_ARMV8 static void bxory(unsigned char *b, unsigned char *y, size_t num)
{
        int i;

        for(i = 0; i < (int)num; i++) {
                b[i] = b[i] ^ y[i];
        }
}

SMB2_ARMV8 static void armv8_ccm_generate_b0(const unsigned char *nonce, size_t nlen,
                                             size_t alen, size_t plen, size_t mlen,
                                             unsigned char *buf)
{
        unsigned char flags = (unsigned char)(((mlen - 2) / 2) << 3);

        ccm_format_block(buf, nonce, nlen, flags | (alen ? 0x40 : 0), plen);
}

SMB2_ARMV8 static void armv8_ccm_generate_s(const struct smb2_aes128_keys *keys,
                                            const unsigned char *nonce, size_t nlen,
                                            uint64_t counter, unsigned char *s)
{
        ccm_format_block(s, nonce, nlen, 0, counter);

        vst1q_u8(s, smb2_armv8_aes128_encrypt(vld1q_u8(s), keys));
}

SMB2_ARMV8 static void armv8_ccm_generate_T(const struct smb2_aes128_keys *keys,
                                            const unsigned char *nonce, size_t nlen,
                                            const unsigned char *aad, size_t alen,
                                            unsigned char *p, size_t plen,
                                            unsigned char *m, size_t mlen)
{
        unsigned char b[16], y[16];
        uint16_t l;

        armv8_ccm_generate_b0(nonce, nlen, alen, plen, mlen, &b[0]);
        vst1q_u8(y, smb2_armv8_aes128_encrypt(vld1q_u8(b), keys));

        /* Create Aad */
        if (alen) {
                size_t prefix = ccm_encode_aad_length(b, alen);

                l = alen < 16 - prefix ? (uint16_t)alen : (uint16_t)(16 - prefix);
                memcpy(b + prefix, aad, l);
                memset(b + prefix + l, 0, 16 - prefix - l);
                aad  += l;
                alen -= l;

                vst1q_u8(b, veorq_u8(vld1q_u8(b), vld1q_u8(y)));
                vst1q_u8(y, smb2_armv8_aes128_encrypt(vld1q_u8(b), keys));

                while (alen) {
                        memset(b, 0, 16);
                        l = (alen > 16) ? 16 : (uint16_t)alen;
                        memcpy(b, aad, l);
                        aad  += l;
                        alen -= l;

                        vst1q_u8(b, veorq_u8(vld1q_u8(b), vld1q_u8(y)));
                        vst1q_u8(y, smb2_armv8_aes128_encrypt(vld1q_u8(b), keys));
                }
        }

        /* Create Payload */
        while (plen) {
                memset(b, 0, 16);
                l = (plen > 16) ? 16 : (uint16_t)plen;
                memcpy(b, p, l);
                p    += l;
                plen -= l;

                vst1q_u8(b, veorq_u8(vld1q_u8(b), vld1q_u8(y)));
                vst1q_u8(y, smb2_armv8_aes128_encrypt(vld1q_u8(b), keys));
        }

        memcpy(m, y, mlen);
}

SMB2_ARMV8 static void armv8_ccm_crypt(const struct smb2_aes128_keys *keys,
                                       const unsigned char *nonce, size_t nlen,
                                       unsigned char *p, size_t plen)
{
        unsigned char s[16];
        size_t l;
        uint64_t counter = 1;

        while (plen) {
                l = (plen > 16) ? 16 : plen;
                armv8_ccm_generate_s(keys, nonce, nlen, counter, &s[0]);
                bxory(p, &s[0], l);

                counter++;
                p += l;
                plen -= l;
        }
}

SMB2_ARMV8 int aes128ccm_armv8_encrypt(unsigned char *key,
                                       unsigned char *nonce, size_t nlen,
                                       unsigned char *aad, size_t alen,
                                       unsigned char *p, size_t plen,
                                       unsigned char *m, size_t mlen)
{
        struct smb2_aes128_keys keys;
        unsigned char s[16];

        if (!ccm_valid_lengths(nlen, plen, mlen)) {
                return -1;
        }
        smb2_armv8_aes128_expand_key(key, &keys);

        armv8_ccm_generate_T(&keys, nonce, nlen, aad, alen, p, plen, m, mlen);
        armv8_ccm_generate_s(&keys, nonce, nlen, 0, &s[0]);
        bxory(m, &s[0], mlen);

        armv8_ccm_crypt(&keys, nonce, nlen, p, plen);

        return 0;
}

SMB2_ARMV8 int aes128ccm_armv8_decrypt(unsigned char *key,
                                       unsigned char *nonce, size_t nlen,
                                       unsigned char *aad, size_t alen,
                                       unsigned char *p, size_t plen,
                                       unsigned char *m, size_t mlen)
{
        struct smb2_aes128_keys keys;
        unsigned char s[16];
        unsigned char tmp[16];

        if (!ccm_valid_lengths(nlen, plen, mlen)) {
                return -1;
        }
        smb2_armv8_aes128_expand_key(key, &keys);

        armv8_ccm_crypt(&keys, nonce, nlen, p, plen);

        armv8_ccm_generate_T(&keys, nonce, nlen, aad, alen, p, plen, tmp, mlen);
        armv8_ccm_generate_s(&keys, nonce, nlen, 0, &s[0]);
        bxory(tmp, &s[0], mlen);

        return memcmp(tmp, m, mlen);
}

#endif /* SMB2_ARMV8_AES */
