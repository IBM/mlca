// SPDX-License-Identifier: Apache-2.0
/**
 * @file random_default.h
 * 
 * Include this header to define the default RNG.
 * In a test build, the default is AESCTR-DRBG.
 * In a productive build, the default is tghe system RNG.
 * 
 */

#ifndef RANDOM_DEFAULT_H
#define RANDOM_DEFAULT_H

#ifdef TEST_BUILD
#include <random_nist.h>
#define RANDOM_DEFAULT random_ctrdrbg
#else
#include <random_system.h>
#define RANDOM_DEFAULT random_system
#endif

#endif