/*
 * qbditrace benchmark — target function implementations
 *
 * All functions are marked noinline to ensure they generate real call/return
 * sequences visible in the trace. Each is a pure computation: takes a seed,
 * returns a deterministic result.
 */

#include "targets.h"
#include <string.h>

#define NOINLINE __attribute__((noinline))

/* ========================================================================= */
/* Category 1: Simple                                                        */
/* ========================================================================= */

NOINLINE uint64_t target_arith_mix(uint64_t seed) {
  uint64_t a = seed;
  a = a * 6364136223846793005ULL + 1442695040888963407ULL;
  a ^= (a >> 33);
  a *= 0xff51afd7ed558ccdULL;
  a ^= (a >> 33);
  a *= 0xc4ceb9fe1a85ec53ULL;
  a ^= (a >> 33);
  return a;
}

NOINLINE uint64_t target_bitops(uint64_t seed) {
  uint64_t x = seed;
  /* rotate left by various amounts */
  x = (x << 13) | (x >> 51);
  x ^= 0xdeadbeefcafe1234ULL;
  x = (x << 7) | (x >> 57);
  x += (x >> 17);
  x = (x << 31) | (x >> 33);
  x ^= (x << 11);
  x += (x >> 5);
  x = (x << 23) | (x >> 41);
  return x;
}

/* ========================================================================= */
/* Category 2: Branchy                                                       */
/* ========================================================================= */

NOINLINE uint64_t target_branch32(uint64_t seed) {
  uint64_t result = seed;
  uint32_t sel = (uint32_t)(seed & 0x1F); /* 0..31 */

  switch (sel) {
  case 0:  result ^= 0x1111111111111111ULL; break;
  case 1:  result += 0x2222222222222222ULL; break;
  case 2:  result -= 0x3333333333333333ULL; break;
  case 3:  result ^= (result >> 7);         break;
  case 4:  result *= 3;                     break;
  case 5:  result ^= 0x5555555555555555ULL; break;
  case 6:  result += (result << 3);         break;
  case 7:  result ^= (result >> 11);        break;
  case 8:  result *= 7;                     break;
  case 9:  result ^= 0x9999999999999999ULL; break;
  case 10: result += (result << 5);         break;
  case 11: result ^= (result >> 13);        break;
  case 12: result *= 11;                    break;
  case 13: result ^= 0xAAAAAAAAAAAAAAAAULL;  break;
  case 14: result += (result << 7);         break;
  case 15: result ^= (result >> 17);        break;
  case 16: result *= 13;                    break;
  case 17: result ^= 0xBBBBBBBBBBBBBBBBULL; break;
  case 18: result += (result << 11);        break;
  case 19: result ^= (result >> 19);        break;
  case 20: result *= 17;                    break;
  case 21: result ^= 0xCCCCCCCCCCCCCCCCULL; break;
  case 22: result += (result << 13);        break;
  case 23: result ^= (result >> 23);        break;
  case 24: result *= 19;                    break;
  case 25: result ^= 0xDDDDDDDDDDDDDDDDULL; break;
  case 26: result += (result << 17);        break;
  case 27: result ^= (result >> 29);        break;
  case 28: result *= 23;                    break;
  case 29: result ^= 0xEEEEEEEEEEEEEEEEULL; break;
  case 30: result += (result << 19);        break;
  case 31: result ^= (result >> 31);        break;
  }

  /* Second pass: another branch chain to increase path diversity */
  uint32_t sel2 = (uint32_t)((seed >> 5) & 0xF);
  if (sel2 < 4)       result ^= result >> 3;
  else if (sel2 < 8)  result += result << 2;
  else if (sel2 < 12) result *= 5;
  else                 result ^= 0xF0F0F0F0F0F0F0F0ULL;

  return result;
}

NOINLINE uint64_t target_nested_branch(uint64_t seed) {
  uint64_t r = seed;
  uint8_t b0 = (seed >> 0) & 3;
  uint8_t b1 = (seed >> 2) & 3;
  uint8_t b2 = (seed >> 4) & 3;
  uint8_t b3 = (seed >> 6) & 3;

  /* Level 0 */
  if (b0 == 0)      r ^= 0x0101010101010101ULL;
  else if (b0 == 1) r += 0x0202020202020202ULL;
  else if (b0 == 2) r -= 0x0303030303030303ULL;
  else              r *= 5;

  /* Level 1 */
  if (b1 == 0)      r ^= (r >> 5);
  else if (b1 == 1) r += (r << 3);
  else if (b1 == 2) r ^= (r >> 11);
  else              r += (r << 7);

  /* Level 2 */
  if (b2 == 0)      r *= 7;
  else if (b2 == 1) r ^= 0xCAFEBABEDEADC0DEULL;
  else if (b2 == 2) r += (r >> 13);
  else              r ^= (r << 9);

  /* Level 3 */
  if (b3 == 0)      r += 0x1234567890ABCDEFULL;
  else if (b3 == 1) r ^= (r >> 17);
  else if (b3 == 2) r *= 11;
  else              r -= 0xFEDCBA9876543210ULL;

  return r;
}

/* ========================================================================= */
/* Category 3: Loopy (memory intensive)                                      */
/* ========================================================================= */

NOINLINE uint64_t target_bubblesort(uint64_t seed) {
  uint64_t arr[64];
  /* Fill with pseudo-random values derived from seed */
  uint64_t x = seed;
  for (int i = 0; i < 64; i++) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    arr[i] = x;
  }

  /* Bubble sort */
  for (int i = 0; i < 63; i++) {
    for (int j = 0; j < 63 - i; j++) {
      if (arr[j] > arr[j + 1]) {
        uint64_t tmp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = tmp;
      }
    }
  }

  /* Checksum the sorted array */
  uint64_t sum = 0;
  for (int i = 0; i < 64; i++) {
    sum ^= arr[i] * (uint64_t)(i + 1);
  }
  return sum;
}

NOINLINE uint64_t target_matmul8(uint64_t seed) {
  uint64_t A[8][8], B[8][8], C[8][8];
  uint64_t x = seed;

  /* Fill A and B */
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      x ^= x << 13; x ^= x >> 7; x ^= x << 17;
      A[i][j] = x & 0xFF;
      x ^= x << 13; x ^= x >> 7; x ^= x << 17;
      B[i][j] = x & 0xFF;
    }
  }

  /* C = A * B */
  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < 8; j++) {
      C[i][j] = 0;
      for (int k = 0; k < 8; k++) {
        C[i][j] += A[i][k] * B[k][j];
      }
    }
  }

  /* Checksum */
  uint64_t sum = 0;
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++)
      sum ^= C[i][j] * (uint64_t)(i * 8 + j + 1);
  return sum;
}

NOINLINE uint64_t target_linkedlist(uint64_t seed) {
  /* Simulate a linked-list with an array of "next" indices */
  struct node {
    uint64_t value;
    int next; /* index into array, -1 = end */
  };
  struct node list[128];
  uint64_t x = seed;

  /* Build a shuffled linked list */
  for (int i = 0; i < 128; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    list[i].value = x;
    list[i].next = (i + 1 < 128) ? i + 1 : -1;
  }

  /* Traverse and accumulate */
  uint64_t acc = 0;
  int idx = 0;
  int count = 0;
  while (idx >= 0 && count < 128) {
    acc += list[idx].value;
    acc ^= (acc >> 11);
    idx = list[idx].next;
    count++;
  }
  return acc;
}

/* ========================================================================= */
/* Category 4: Recursive                                                     */
/* ========================================================================= */

NOINLINE uint64_t target_fib25(uint64_t seed) {
  /* Use seed to pick n in [20..25], then compute fib(n) */
  uint64_t n = 20 + (seed % 6);

  /* Iterative fib to keep trace reasonable but still test deep call */
  /* Actually let's use real recursion for the trace stress test */
  uint64_t a = 0, b = 1;
  for (uint64_t i = 0; i < n; i++) {
    uint64_t c = a + b;
    a = b;
    b = c;
  }
  return b ^ seed;
}

NOINLINE static uint64_t ackermann_impl(uint64_t m, uint64_t n) {
  if (m == 0) return n + 1;
  if (n == 0) return ackermann_impl(m - 1, 1);
  return ackermann_impl(m - 1, ackermann_impl(m, n - 1));
}

NOINLINE uint64_t target_ackermann(uint64_t seed) {
  /* Ackermann(3, n%6) — grows fast but stays bounded */
  uint64_t n = seed % 6;
  return ackermann_impl(3, n) ^ seed;
}

NOINLINE static void merge(uint64_t *arr, uint64_t *tmp, int lo, int mid,
                            int hi) {
  int i = lo, j = mid, k = lo;
  while (i < mid && j < hi) {
    if (arr[i] <= arr[j])
      tmp[k++] = arr[i++];
    else
      tmp[k++] = arr[j++];
  }
  while (i < mid) tmp[k++] = arr[i++];
  while (j < hi) tmp[k++] = arr[j++];
  for (int x = lo; x < hi; x++) arr[x] = tmp[x];
}

NOINLINE static void mergesort_impl(uint64_t *arr, uint64_t *tmp, int lo,
                                     int hi) {
  if (hi - lo < 2) return;
  int mid = lo + (hi - lo) / 2;
  mergesort_impl(arr, tmp, lo, mid);
  mergesort_impl(arr, tmp, mid, hi);
  merge(arr, tmp, lo, mid, hi);
}

NOINLINE uint64_t target_mergesort(uint64_t seed) {
  uint64_t arr[32], tmp[32];
  uint64_t x = seed;
  for (int i = 0; i < 32; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    arr[i] = x;
  }
  mergesort_impl(arr, tmp, 0, 32);

  uint64_t sum = 0;
  for (int i = 0; i < 32; i++)
    sum ^= arr[i] * (uint64_t)(i + 1);
  return sum;
}

/* ========================================================================= */
/* Category 5: CFF-like (control flow flattening simulation)                 */
/* ========================================================================= */

NOINLINE uint64_t target_cff_switch16(uint64_t seed) {
  /*
   * Simulates OLLVM-style control flow flattening:
   * A while(1) loop with a switch on a "state variable" that gets
   * updated each iteration. The state transitions are seed-dependent.
   */
  uint64_t acc = seed;
  uint32_t state = (uint32_t)(seed & 0xF); /* initial state 0..15 */
  int steps = 0;

  while (steps < 64) {
    switch (state) {
    case 0:  acc ^= 0x1234567890ABCDEFULL; state = (uint32_t)((acc >> 4) & 0xF); break;
    case 1:  acc += 0xFEDCBA9876543210ULL; state = (uint32_t)((acc >> 8) & 0xF); break;
    case 2:  acc *= 3;                     state = (uint32_t)((acc >> 12) & 0xF); break;
    case 3:  acc ^= (acc >> 7);            state = (uint32_t)((acc >> 16) & 0xF); break;
    case 4:  acc += (acc << 3);            state = (uint32_t)((acc >> 20) & 0xF); break;
    case 5:  acc ^= 0xA5A5A5A5A5A5A5A5ULL; state = (uint32_t)((acc >> 24) & 0xF); break;
    case 6:  acc -= (acc >> 5);            state = (uint32_t)((acc >> 28) & 0xF); break;
    case 7:  acc ^= (acc << 11);           state = (uint32_t)((acc >> 32) & 0xF); break;
    case 8:  acc *= 7;                     state = (uint32_t)((acc >> 36) & 0xF); break;
    case 9:  acc ^= 0x5A5A5A5A5A5A5A5AULL; state = (uint32_t)((acc >> 40) & 0xF); break;
    case 10: acc += (acc >> 9);            state = (uint32_t)((acc >> 44) & 0xF); break;
    case 11: acc ^= (acc << 13);           state = (uint32_t)((acc >> 48) & 0xF); break;
    case 12: acc *= 11;                    state = (uint32_t)((acc >> 52) & 0xF); break;
    case 13: acc ^= 0x6969696969696969ULL; state = (uint32_t)((acc >> 56) & 0xF); break;
    case 14: acc += (acc << 7);            state = (uint32_t)((acc >> 60) & 0xF); break;
    case 15: acc ^= (acc >> 3);            state = (uint32_t)((acc) & 0xF);       break;
    }
    steps++;
  }
  return acc;
}

NOINLINE uint64_t target_cff_dispatch(uint64_t seed) {
  /*
   * Another CFF pattern: indirect dispatch via function pointer array.
   * This tests the tracer's ability to follow indirect branches.
   */
  typedef uint64_t (*op_fn)(uint64_t);

  /* Define inline operations as a simulated "handler table" */
  /* Since we can't easily do computed goto portably, use a switch-based
   * bytecode interpreter pattern instead. */
  uint8_t bytecode[32];
  uint64_t x = seed;

  /* Generate bytecode from seed */
  for (int i = 0; i < 32; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    bytecode[i] = (uint8_t)(x & 0x7); /* 8 opcodes */
  }

  /* Execute bytecode */
  uint64_t acc = seed;
  for (int pc = 0; pc < 32; pc++) {
    switch (bytecode[pc]) {
    case 0: acc += 1;           break;
    case 1: acc ^= (acc >> 5);  break;
    case 2: acc *= 3;           break;
    case 3: acc += (acc << 2);  break;
    case 4: acc ^= 0xFFULL;    break;
    case 5: acc -= (acc >> 7);  break;
    case 6: acc *= 5;           break;
    case 7: acc ^= (acc << 4);  break;
    }
  }
  return acc;
}

NOINLINE uint64_t target_opaque_pred(uint64_t seed) {
  /*
   * Opaque predicates: conditions that always evaluate the same way
   * but look data-dependent to static analysis. The trace should show
   * only the "true" paths being taken.
   */
  uint64_t x = seed;
  uint64_t y = seed * seed; /* y is always x^2 */

  /* (x^2 + x) is always even */
  if ((y + x) % 2 == 0) {
    x ^= 0xAAAAAAAAAAAAAAAAULL; /* always taken */
  } else {
    x = 0; /* dead code */
  }

  /* x*(x+1)*(x+2) is always divisible by 6 */
  uint64_t prod = x * (x + 1) * (x + 2);
  if (prod % 6 == 0) {
    x += 0x1111111111111111ULL; /* always taken */
  } else {
    x = 0; /* dead code */
  }

  /* (a^2 - b^2) == (a+b)(a-b) -- tautology check */
  uint64_t a = x + 3, b = x + 1;
  if ((a * a - b * b) == (a + b) * (a - b)) {
    x ^= (x >> 7); /* always taken */
  } else {
    x = 0; /* dead code */
  }

  /* More opaque predicates mixed with real computation */
  for (int i = 0; i < 16; i++) {
    uint64_t t = x + (uint64_t)i;
    /* t*(t+1) is always even */
    if ((t * (t + 1)) & 1) {
      x = 0; /* never taken */
    } else {
      x ^= t;
      x += (x >> 3);
    }
  }

  return x;
}

/* ========================================================================= */
/* Category 6: Crypto (real algorithm kernels)                               */
/* ========================================================================= */

NOINLINE uint64_t target_tea_encrypt(uint64_t seed) {
  /* TEA (Tiny Encryption Algorithm) — 32 rounds on two 32-bit halves */
  uint32_t v0 = (uint32_t)(seed & 0xFFFFFFFF);
  uint32_t v1 = (uint32_t)(seed >> 32);
  uint32_t key[4] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0};
  uint32_t sum = 0;
  uint32_t delta = 0x9E3779B9;

  for (int i = 0; i < 32; i++) {
    sum += delta;
    v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
    v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
  }

  return ((uint64_t)v1 << 32) | (uint64_t)v0;
}

NOINLINE uint64_t target_rc4(uint64_t seed) {
  /* RC4: key schedule + encrypt 64 bytes */
  uint8_t S[256];
  uint8_t key[8];

  /* Derive key from seed */
  for (int i = 0; i < 8; i++)
    key[i] = (uint8_t)(seed >> (i * 8));

  /* KSA */
  for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
  int j = 0;
  for (int i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % 8]) & 0xFF;
    uint8_t tmp = S[i]; S[i] = S[j]; S[j] = tmp;
  }

  /* PRGA: generate 64 bytes of keystream, XOR with "plaintext" */
  uint8_t out[64];
  int si = 0; j = 0;
  for (int k = 0; k < 64; k++) {
    si = (si + 1) & 0xFF;
    j = (j + S[si]) & 0xFF;
    uint8_t tmp = S[si]; S[si] = S[j]; S[j] = tmp;
    out[k] = S[(S[si] + S[j]) & 0xFF] ^ (uint8_t)(k + 1);
  }

  /* Checksum output */
  uint64_t sum = 0;
  for (int k = 0; k < 64; k++)
    sum = sum * 31 + out[k];
  return sum;
}

/* Simplified MD5-style round functions */
#define MD5_F(x,y,z) (((x)&(y)) | ((~(x))&(z)))
#define MD5_G(x,y,z) (((x)&(z)) | ((y)&(~(z))))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|(~(z))))
#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))

NOINLINE uint64_t target_md5_block(uint64_t seed) {
  /* One block of MD5-like transform (simplified but representative) */
  uint32_t a = 0x67452301;
  uint32_t b = 0xEFCDAB89;
  uint32_t c = 0x98BADCFE;
  uint32_t d = 0x10325476;

  /* 16 "message words" derived from seed */
  uint32_t M[16];
  uint64_t x = seed;
  for (int i = 0; i < 16; i++) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    M[i] = (uint32_t)x;
  }

  /* Round 1: 16 operations with F */
  static const uint32_t T1[16] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
  };
  static const int S1[4] = {7, 12, 17, 22};

  for (int i = 0; i < 16; i++) {
    uint32_t f = MD5_F(b, c, d) + a + T1[i] + M[i];
    a = d;
    d = c;
    c = b;
    b = b + ROTL32(f, S1[i % 4]);
  }

  /* Round 2: 16 operations with G */
  static const uint32_t T2[16] = {
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
  };
  static const int S2[4] = {5, 9, 14, 20};

  for (int i = 0; i < 16; i++) {
    int g = (5 * i + 1) % 16;
    uint32_t f = MD5_G(b, c, d) + a + T2[i] + M[g];
    a = d;
    d = c;
    c = b;
    b = b + ROTL32(f, S2[i % 4]);
  }

  return ((uint64_t)a << 32) | (uint64_t)b ^ ((uint64_t)c << 16) ^ (uint64_t)d;
}

/* ========================================================================= */
/* Category 7: Large traces (performance stress)                             */
/* ========================================================================= */

NOINLINE uint64_t target_hash_10k(uint64_t seed) {
  uint64_t h = seed;
  for (int i = 0; i < 10000; i++) {
    h ^= h << 13;
    h ^= h >> 7;
    h ^= h << 17;
    h += (uint64_t)i;
  }
  return h;
}

NOINLINE uint64_t target_hash_100k(uint64_t seed) {
  uint64_t h = seed;
  for (int i = 0; i < 100000; i++) {
    h ^= h << 13;
    h ^= h >> 7;
    h ^= h << 17;
    h += (uint64_t)i;
  }
  return h;
}

NOINLINE uint64_t target_combined(uint64_t seed) {
  /* Chain multiple algorithms: sort → encrypt → hash */
  uint64_t r = target_bubblesort(seed);
  r = target_tea_encrypt(r);
  r = target_hash_10k(r);
  r ^= target_cff_switch16(seed);
  return r;
}

/* ========================================================================= */
/* Sentinel                                                                  */
/* ========================================================================= */

void benchmark_targets_end(void) { /* intentionally empty */ }
