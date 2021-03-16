#ifndef TSC_H
#define TSC_H

/**
 * tsc.h - support for using the TSC register on intel machines as a timing
 * method. Should compile with -O to ensure inline attribute is honoured.
 *
 * author: David Terei <code@davidterei.com>
 * copyright: Copyright (c) 2016, David Terei
 * license: BSD
 */

#include <stdint.h>
#include <stdlib.h>

#define TSC_OVERHEAD_N 1000

// bench_start returns a timestamp for use to measure the start of a benchmark
// run.
static inline uint64_t bench_start(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "CPUID\n\t" // serialize
                "RDTSC\n\t" // read clock
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

// bench_end returns a timestamp for use to measure the end of a benchmark run.
static inline uint64_t bench_end(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "RDTSCP\n\t" // read clock + serialize
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                "CPUID\n\t" // serialze -- but outside clock region!
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

// measure_tsc_overhead returns the overhead from benchmarking, it should be
// subtracted from timings to improve accuracy.
static uint64_t measure_tsc_overhead(void)
{
  uint64_t t0, t1, overhead = ~0;
  int i;

  for (i = 0; i < TSC_OVERHEAD_N; i++) {
    t0 = bench_start();
    asm volatile("");
    t1 = bench_end();
    if (t1 - t0 < overhead)
      overhead = t1 - t0;
  }

  return overhead;
}

static int cmp_llu(const void *a, const void*b){
    if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
    if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen){
    qsort(l,llen,sizeof(unsigned long long),cmp_llu);
    if(llen%2) return l[llen/2];
    else return (l[llen/2-1]+l[llen/2])/2;
}

/*
#define MEASURE(X, Y) \
    {\
    uint64_t M_start, M_end, M_overhead;\
    int M_i;\
    M_results = malloc(M_trials*sizeof(uint64_t));\
    M_overhead = measure_tsc_overhead();\
    for(M_i=0; M_i < M_trials; M_i++){\
        M_start = bench_start();\
        X;\
        M_end = bench_end();\
        M_results[M_i] = M_end-M_start-M_overhead;\
        Y;\
    }\
    }\
*/



static uint64_t measure(int trials, void (*f)(void)){
    uint64_t start, end, overhead;
    uint64_t *results;
    int i;
    
    results = malloc(trials*sizeof(uint64_t));

    overhead = measure_tsc_overhead();
    for(i=0; i < trials; i++){
        start = bench_start();
        f();
        end = bench_end();
        
        results[i] = end-start-overhead;
    }

    free(results);

    return median((long long unsigned *)results, trials);
}

#endif /* TSC_H */