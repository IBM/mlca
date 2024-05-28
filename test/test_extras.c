// SPDX-License-Identifier: Apache-2.0 and MIT
#include <time.h>
#include <stdlib.h>
#include <mlca2.h>
#include <stdio.h>

#include "test_extras.h"
#if (OS_TARGET == OS_UNIX) && (TARGET_PLATFORM != TARGET_AMD64 && TARGET_PLATFORM != TARGET_x86 && TARGET_PLATFORM != TARGET_S390X)
#include <time.h>
#endif
#include <stdlib.h>


int64_t cpucycles(void) {
#if (TARGET_PLATFORM == TARGET_AMD64 || TARGET_PLATFORM == TARGET_x86)
  unsigned int hi, lo;

  asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
  return ((int64_t) lo) | (((int64_t) hi) << 32);
#elif (TARGET_PLATFORM == TARGET_S390X)
    uint64_t tod;
    asm volatile("stckf %0\n" : "=Q" (tod) : : "cc");
    return (tod*1000/4096);
#else
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec*1e9 + time.tv_nsec);

#endif
}

void print_hex(const char* title, const unsigned char* seq, size_t seqLen, int newline) {
  if (title)
    printf("%s: ", title);
  for (int i = 0; i < seqLen; ++i) {
    printf("%02X", seq[i]);
  }
  if (newline)
      printf("\n");
}
