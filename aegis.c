#include <stdint.h>     //for int8_t
#include <stdio.h>     //for printf
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include "aegis.h"
#include <time.h>

#define STATE_128  5 
#define STATE_128L 8 
#define STATE_256  6 

#define SIZE 1024 * 1024 * 10

static const uint8_t CONST[32] = {
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62, 
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

void print_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

__m128i xor_state_0(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[6], _mm_and_si128(state[2], state[3])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_1(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[2], _mm_xor_si128(state[5], _mm_and_si128(state[6], state[7])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_256(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[4], _mm_xor_si128(state[5], _mm_and_si128(state[2], state[3]))));
    memcpy(state_out, &xor_state, 16);
}

void update_state_128l(__m128i *state, __m128i m_a, __m128i m_b) {
    __m128i tmp = _mm_aesenc_si128(state[7], _mm_xor_si128(state[0], m_a));
    state[7] = _mm_aesenc_si128(state[6], state[7]);
    state[6] = _mm_aesenc_si128(state[5], state[6]);
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], _mm_xor_si128(state[4], m_b));
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = tmp;
}

void update_state_256(__m128i *state, __m128i m) {
    __m128i tmp = _mm_aesenc_si128(state[5], _mm_xor_si128(state[0], m));
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = tmp;
}

void init_state_128l(__m128i *state, __m128i key, __m128i iv) {
    __m128i xor_key_iv = _mm_xor_si128(key, iv);
    __m128i const_0 = _mm_loadu_si128((__m128i *) CONST);
    __m128i const_1 = _mm_loadu_si128((__m128i *) (CONST + 16));
    __m128i xor_key_const_0 = _mm_xor_si128(key, const_0);
    __m128i xor_key_const_1 = _mm_xor_si128(key, const_1);

    state[0] = xor_key_iv;
    state[1] = const_1;
    state[2] = const_0;
    state[3] = const_1;
    state[4] = xor_key_iv;
    state[5] = xor_key_const_0;
    state[6] = xor_key_const_1;
    state[7] = xor_key_const_0;

    uint8_t i = 10;
    while (i--) {
        update_state_128l(state, iv, key);
    }
}

void init_state_256(__m128i *state, __m128i key_0, __m128i key_1, __m128i iv_0, __m128i iv_1) {
    __m128i xor_key_0_iv_0 = _mm_xor_si128(key_0, iv_0);
    __m128i xor_key_1_iv_1 = _mm_xor_si128(key_1, iv_1);
    __m128i const_0 = _mm_loadu_si128((__m128i *) CONST);
    __m128i const_1 = _mm_loadu_si128((__m128i *) (CONST + 16));

    state[0] = xor_key_0_iv_0;
    state[1] = xor_key_1_iv_1;
    state[2] = const_1;
    state[3] = const_0;
    state[4] = _mm_xor_si128(key_0, const_0);
    state[5] = _mm_xor_si128(key_1, const_1);

    uint8_t i = 4;
    while (i--) {
        update_state_256(state, key_0);
        update_state_256(state, key_1);
        update_state_256(state, xor_key_0_iv_0);
        update_state_256(state, xor_key_1_iv_1);
    }
}

void process_ad_128l(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 5) << 5;
    while (l != full_block_len) {
        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) (ad + l)), 
            _mm_loadu_si128((__m128i *) (ad + l + 16))
        );
        l += 32;
    }

    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);
        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) last_block), 
            _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void process_ad_256(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 4) << 4;
    while (l != full_block_len) {
        update_state_256(state, _mm_loadu_si128((__m128i *) (ad + l)));
        l += 16;
    }

    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);
        update_state_256(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

void encrypt_128l(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    size_t l = 0;
    size_t full_block_len = (plain_len >> 5) << 5;

    uint8_t state_0[16];
    uint8_t state_1[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            cipher[l + i] = plain[l + i] ^ state_0[i];
            cipher[l + i + 16] = plain[l + i + 16] ^ state_1[i];
        }
        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) (plain + l)), 
            _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
        l += 32;
    }

    size_t diff = plain_len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, plain + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);

        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            cipher[l + i] = last_block[i] ^ state_0[i];
            cipher[l + i + 16] = last_block[i + 16] ^ state_1[i];
        }

        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) last_block), 
            _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void encrypt_256(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    size_t l = 0;
    size_t full_block_len = (plain_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_256(state, state_0);
        i = 16;
        while(i--) {
            cipher[l + i] = plain[l + i] ^ state_0[i];
        }
        update_state_256(state, _mm_loadu_si128((__m128i *) (plain + l)));
        l += 16;
    }

    size_t diff = plain_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, plain + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_256(state, state_0);
        i = 16;
        while(i--) {
            cipher[l + i] = last_block[i] ^ state_0[i];
        }

        update_state_256(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

void decrypt_128l(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    size_t l = 0;
    size_t full_block_len = (cipher_len >> 5) << 5;

    uint8_t state_0[16];
    uint8_t state_1[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            plain[l + i] = cipher[l + i] ^ state_0[i];
            plain[l + i + 16] = cipher[l + i + 16] ^ state_1[i];
        }
        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) (plain + l)), 
            _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
        l += 32;
    }

    size_t diff = cipher_len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, cipher + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);

        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            plain[l + i] = last_block[i] ^ state_0[i];
            plain[l + i + 16] = last_block[i + 16] ^ state_1[i];
        }
        memset(plain + l + diff, 0, 32 - diff);

        update_state_128l(state, 
            _mm_loadu_si128((__m128i *) (plain + l)), 
            _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
    }
}

void decrypt_256(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    size_t l = 0;
    size_t full_block_len = (cipher_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_256(state, state_0);
        i = 16;
        while(i--) {
            plain[l + i] = cipher[l + i] ^ state_0[i];
        }
        update_state_256(state, _mm_loadu_si128((__m128i *) (plain + l)));
        l += 16;
    }

    size_t diff = cipher_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, cipher + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_256(state, state_0);
        i = 16;
        while(i--) {
            plain[l + i] = last_block[i] ^ state_0[i];
        }
        memset(plain + l + diff, 0, 16 - diff);

        update_state_256(state, _mm_loadu_si128((__m128i *) (plain + l)));
    }
}

void finalize_128l(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    __m128i  msgtmp;
    uint8_t tmp[16];
    memset(tmp, 0, 16);

    ((unsigned long long *) tmp)[0] = ad_len << 3; 
    ((unsigned long long *) tmp)[1] = plain_len << 3; 
    msgtmp = _mm_load_si128((__m128i *) tmp);
    msgtmp = _mm_xor_si128(msgtmp, state[2]);

    uint8_t i;
    i = 7;
    while (i--) {
        update_state_128l(state, msgtmp, msgtmp);
    }

    uint8_t j;
    memset(tag, 0, 16);
    i = 7;
    while (i--) {
        uint8_t *st = (uint8_t *) &state[i];
        j = 16;
        while (j--) {
            tag[j] ^= st[j];
        }
    }
}

void finalize_256(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    __m128i  msgtmp;
    uint8_t tmp[16];
    memset(tmp, 0, 16);

    ((unsigned long long *) tmp)[0] = ad_len << 3; 
    ((unsigned long long *) tmp)[1] = plain_len << 3; 
    msgtmp = _mm_load_si128((__m128i *) tmp);
    msgtmp = _mm_xor_si128(msgtmp, state[3]);

    uint8_t i;
    i = 7;
    while (i--) {
        update_state_256(state, msgtmp);
    }

    uint8_t j;
    memset(tag, 0, 16);
    i = 6;
    while (i--) {
        uint8_t *st = (uint8_t *) &state[i];
        j = 16;
        while (j--) {
            tag[j] ^= st[j];
        }
    }
}

/**
 * encrypt using AEGIS-128L
 *
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param msg, len = @param msglen * 8
 * @param msglen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * OUTPUT:
 * @param tag 128bit
 * @param cipher, len = @param msglen
 */
void aegis_128l_encrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *msg, size_t msglen,
    const uint8_t *ad, size_t adlen,
    uint8_t *tag, uint8_t *cipher
) {
    __m128i state[STATE_128L];
    init_state_128l(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad_128l(state, ad, adlen);
    encrypt_128l(state, msg, msglen, cipher);
    finalize_128l(state, adlen, msglen, tag);
}

/**
 * decrypt using AEGIS-128L
 *
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param cipher, len = @param cipherlen * 8
 * @param cipherlen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * @param tag 128bit
 * OUTPUT:
 * @param msg, len = @param cipherlen
 * @return 1 if tag is valid, 0 otherwise
 */
uint8_t aegis_128l_decrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *cipher, size_t cipherlen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *tag, uint8_t *msg
) {
    __m128i state[STATE_128L];
    init_state_128l(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad_128l(state, ad, adlen);
    decrypt_128l(state, cipher, cipherlen, msg);

    uint8_t tag_internal[16];
    finalize_128l(state, adlen, cipherlen, tag_internal);
    return !memcmp(tag, tag_internal, 16);
}

/**
 * encrypt using AEGIS-256
 *
 * INPUT:
 * @param key 256bit
 * @param iv 256bit
 * @param msg, len = @param msglen * 8
 * @param msglen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * OUTPUT:
 * @param tag 128bit
 * @param cipher, len = @param msglen
 */
void aegis_256_encrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *msg, size_t msglen,
    const uint8_t *ad, size_t adlen,
    uint8_t *tag, uint8_t *cipher
) {
    __m128i state[STATE_256];
    init_state_256(state, 
        _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) (key + 16)), 
        _mm_loadu_si128((__m128i *) iv), _mm_loadu_si128((__m128i *) (iv + 16))
    );
    process_ad_256(state, ad, adlen);
    encrypt_256(state, msg, msglen, cipher);
    finalize_256(state, adlen, msglen, tag);
}

/**
 * decrypt using AEGIS-256
 *
 * INPUT:
 * @param key 256bit
 * @param iv 256bit
 * @param cipher, len = @param cipherlen * 8
 * @param cipherlen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * @param tag 128bit
 * OUTPUT:
 * @param msg, len = @param cipherlen
 * @return 1 if tag is valid, 0 otherwise
 */
uint8_t aegis_256_decrypt(
    const uint8_t *key, const uint8_t *iv,
    const uint8_t *cipher, size_t cipherlen,
    const uint8_t *ad, size_t adlen,
    const uint8_t *tag, uint8_t *msg
) {
    __m128i state[STATE_256];
    init_state_256(state, 
        _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) (key + 16)), 
        _mm_loadu_si128((__m128i *) iv), _mm_loadu_si128((__m128i *) (iv + 16))
    );
    process_ad_256(state, ad, adlen);
    decrypt_256(state, cipher, cipherlen, msg);

    uint8_t tag_internal[16];
    finalize_256(state, adlen, cipherlen, tag_internal);
    return !memcmp(tag, tag_internal, 16);
}

void test_128l() {
    printf("-------- AEGIS-128L: --------\n");

    uint8_t key[16];
    memset(key, 0, 16);

    uint8_t iv[16];
    memset(iv, 0, 16);
    
    size_t ad_len = 0;
    uint8_t *ad = (uint8_t *) malloc(ad_len);
    memset(ad, 0, ad_len);
    
    size_t plain_len = 16;
    uint8_t *plain = (uint8_t *) malloc(plain_len);
    memset(plain, 0, plain_len);

    printf("key    = ");
    print_data(key, 16);
    printf("iv     = ");
    print_data(iv, 16);
    printf("ad     = ");
    print_data(ad, ad_len);
    printf("plain  = ");
    print_data(plain, plain_len);

    uint8_t *cipher = (uint8_t *) malloc(plain_len);
    uint8_t *decr = (uint8_t *) malloc(plain_len);
    uint8_t tag[16];

    aegis_128l_encrypt(key, iv, plain, plain_len, ad, ad_len, tag, cipher);

    printf("cipher = ");
    print_data(cipher, plain_len);
    printf("tag    = ");
    print_data(tag, 16);

    uint8_t success = aegis_128l_decrypt(key, iv, cipher, plain_len, ad, ad_len, tag, decr);
    printf("plain  = ");
    print_data(decr, plain_len);
    if (success) {
        clock_t start, end;
        int t = SIZE;
        start = clock();
        while(t--) {
            aegis_128l_encrypt(key, iv, plain, plain_len, ad, ad_len, tag, cipher);
        }
        end = clock();

        double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        double speed = ((double) SIZE * plain_len) / cpu_time_used / 1048576;
        printf("time used = %.3fs\n", cpu_time_used);
        printf("approx. speed = %.3fMBps\n", speed);
    } else {
        printf("TAG NOT VALID!!\n");
    }
    free(ad);
    free(plain);
    free(cipher);
    free(decr);
}

void test_256() {
    printf("-------- AEGIS-256: --------\n");

    uint8_t key[32];
    memset(key, 1, 32);

    uint8_t iv[32];
    memset(iv, 1, 32);
    
    size_t ad_len = 16;
    uint8_t *ad = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    
    size_t plain_len = 16;
    uint8_t *plain = (uint8_t *) malloc(plain_len);
    memset(plain, 1, plain_len);

    printf("key    = ");
    print_data(key, 32);
    printf("iv     = ");
    print_data(iv, 32);
    printf("ad     = ");
    print_data(ad, ad_len);
    printf("plain  = ");
    print_data(plain, plain_len);

    uint8_t *cipher = (uint8_t *) malloc(plain_len);
    uint8_t *decr = (uint8_t *) malloc(plain_len);
    uint8_t tag[16];

    aegis_256_encrypt(key, iv, plain, plain_len, ad, ad_len, tag, cipher);

    printf("cipher = ");
    print_data(cipher, plain_len);
    printf("tag    = ");
    print_data(tag, 16);

    uint8_t success = aegis_256_decrypt(key, iv, cipher, plain_len, ad, ad_len, tag, decr);
    printf("plain  = ");
    print_data(decr, plain_len);
    if (success) {
        clock_t start, end;
        int t = SIZE;
        start = clock();
        while(t--) {
            aegis_256_encrypt(key, iv, plain, plain_len, ad, ad_len, tag, cipher);
        }
        end = clock();

        double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        double speed = ((double) SIZE * plain_len) / cpu_time_used / 1048576;
        printf("time used = %.3fs\n", cpu_time_used);
        printf("approx. speed = %.3fMBps\n", speed);
    } else {
        printf("TAG NOT VALID!\n");
    }
    free(ad);
    free(plain);
    free(cipher);
    free(decr);
}

int main(int argc, const char *argv[]) {

    // test_128l();
    test_256();
    return 0;
}