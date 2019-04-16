#include <stdint.h>     //for int8_t
#include <stdio.h>     //for printf
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <time.h>

#define STATE_128_COUNT 8 // 8 * 128 bit = 640 bit

#define SIZE 1024 * 64 * 64// 64MB

#define UPDSTATE(state, m_a, m_b) \
    __m128i tmp = _mm_aesenc_si128(state[7], _mm_xor_si128(state[0], m_a)); \
    state[7] = _mm_aesenc_si128(state[6], state[7]); \
    state[6] = _mm_aesenc_si128(state[5], state[6]); \
    state[5] = _mm_aesenc_si128(state[4], state[5]); \
    state[4] = _mm_aesenc_si128(state[3], _mm_xor_si128(state[4], m_b)); \
    state[3] = _mm_aesenc_si128(state[2], state[3]); \
    state[2] = _mm_aesenc_si128(state[1], state[2]); \
    state[1] = _mm_aesenc_si128(state[0], state[1]); \
    state[0] = tmp;

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

void update_state(__m128i *state, __m128i m_a, __m128i m_b) {
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

void init_state(__m128i *state, __m128i key, __m128i iv) {
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
        UPDSTATE(state, iv, key);
    }
}

void process_ad(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 5) << 5;
    while (l != full_block_len) {
        UPDSTATE(state, 
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
        UPDSTATE(state, 
            _mm_loadu_si128((__m128i *) last_block), 
            _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void encrypt(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
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
        UPDSTATE(state, 
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

        UPDSTATE(state, 
            _mm_loadu_si128((__m128i *) last_block), 
            _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void decrypt(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
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
        UPDSTATE(state, 
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

        UPDSTATE(state, 
            _mm_loadu_si128((__m128i *) (plain + l)), 
            _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
    }
}

void finalize(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
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
        UPDSTATE(state, msgtmp, msgtmp);
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

int main(int argc, const char *argv[]) {

    __m128i state[STATE_128_COUNT];

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
    printf("plain  = ");
    print_data(plain, plain_len);

    uint8_t *cipher = (uint8_t *) malloc(plain_len);
    uint8_t tag[16];

    uint8_t *decrypted_plain = (uint8_t *) malloc(plain_len);

    clock_t start, end;
    int t = SIZE;
    start = clock();
    while(t--) {
        init_state(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
        process_ad(state, ad, ad_len);
        encrypt(state, plain, plain_len, cipher);
        finalize(state, ad_len, plain_len, tag);

        // init_state(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
        // process_ad(state, ad, ad_len);
        // decrypt(state, cipher, plain_len, decrypted_plain);
        // finalize(state, ad_len, plain_len, tag);

        // printf("decr   = ");
        // print_data(decrypted_plain, plain_len);

        // printf("tag = ");
        // print_data(tag, 16);
    }
    end = clock();

    printf("cipher (6e99) = ");
    print_data(cipher, plain_len);

    printf("tag    (1ab5) = ");
    print_data(tag, 16);

    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed = ((double) SIZE * plain_len) / cpu_time_used / 1048576;
    printf("time used = %.3fs\n", cpu_time_used);
    printf("approx. speed = %.3fMBps\n", speed);

    // printf()
    printf("done!\n");
    return 0;
}