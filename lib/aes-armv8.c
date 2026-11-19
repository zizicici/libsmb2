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

/* AES-128 SubWord(RotWord(last column)) with no key-indexed loads. */
SMB2_ARMV8 void smb2_armv8_aes128_expand_key(const uint8_t key[16],
                                             struct smb2_aes128_keys *keys)
{
        /* After AESE's ShiftRows these lanes hold S(k13), S(k14),
         * S(k15), S(k12). Broadcast that word to all four columns. */
        static const uint8_t lanes[16] = {9,6,3,12, 9,6,3,12, 9,6,3,12, 9,6,3,12};
        static const uint8_t first_byte[16] = {255,0,0,0, 255,0,0,0, 255,0,0,0, 255,0,0,0};
        uint8x16_t zero = vdupq_n_u8(0);
        uint8x16_t rk = vld1q_u8(key);
        uint8_t rcon = 1;
        int round;

        vst1q_u8(keys->rk[0], rk);
        for (round = 1; round <= 10; round++) {
                uint8x16_t word = vqtbl1q_u8(vaeseq_u8(rk, zero), vld1q_u8(lanes));
                word = veorq_u8(word, vandq_u8(vdupq_n_u8(rcon), vld1q_u8(first_byte)));
                /* Prefix XOR of the four words of the old round key. */
                rk = veorq_u8(rk, vextq_u8(zero, rk, 12));
                rk = veorq_u8(rk, vextq_u8(zero, rk, 8));
                rk = veorq_u8(rk, word);
                vst1q_u8(keys->rk[round], rk);
                rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
        }
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
