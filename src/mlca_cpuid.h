// SPDX-License-Identifier: Apache-2.0
/**
 * @file mlca_cpuid.h
 * 
 * MLCA CPU feature detection.
 * 
 */

#include <mlca2.h>

#if !defined(TARGET_PLATFORM)
#error "No TARGET_PLATFORM defined"
#elif TARGET_PLATFORM == TARGET_S390X
#include <sys/auxv.h>

static int facility_msa6_avail() {
	// Query kimd and check Keccak availability.
	uint64_t kimdqueryp[2] = { 0 };
	unsigned char* src = 0;
	long src_len = 0;
  
	register unsigned long r0 asm("0") = (unsigned long) 0;
	register unsigned long r1 asm("1") = (unsigned long) kimdqueryp;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;
  
	asm volatile(
	       "0:  .insn rre,0xb93e0000,0,%[src]\n"
	       "     brc  1,0b\n" /* handle partial completion */
		   : [src] "+a" (r2), [len] "+d" (r3)
	       : [fc] "d" (r0), [pba] "a" (r1)
	       : "cc","memory");
	return (kimdqueryp[0] >> (63 - 37)) & 1;
}

static void stfle(uint64_t *facs, int size) {
	unsigned long reg0 = size - 1;
	asm volatile(
        "       .insn   rre,0xb9040000,0,%[reg0]\n" /* lgr */
        "       .insn   s,0xb2b00000,%[list]\n" /* stfle */
        "       .insn   rre,0xb9040000,%[reg0],0\n" /* lgr */
		: [reg0] "+&d" (reg0), [list] "+Q" (*facs)
		:
		: "memory", "cc", "0");
}

static int facility_avail(uint64_t *fac, size_t i) {
	return fac[i / 64] >> (63 - (i % 64));
}

static void set_cpu_features(mlca_cpu_features_t *ft) {
	// STFLE bits described in z/Architecture Principles of Operation
	// First check HWCAP if STFLE is available.
	if (!ft->initialized) {
		uint64_t facs[16] = { 0 };
		stfle(facs, 16);
		uint32_t hcap = getauxval(AT_HWCAP);
		ft->hwcap = hcap;
		if (ft->hwcap & HWCAP_S390_STFLE) {
			ft->vector_facility = facility_avail(facs, 129);
			ft->vector_enhancements_facility_1 = facility_avail(facs, 135);
			ft->vector_enhancements_facility_2 = facility_avail(facs, 148);
			ft->message_security_assist = facility_avail(facs, 17);
			if (ft->message_security_assist) {
				ft->message_security_assist_6 = facility_msa6_avail();
			}
		}
		ft->initialized = 1;
	}
}

#else

static void set_cpu_features(mlca_cpu_features_t *ft) {
	ft->initialized = 1;
}

#endif
