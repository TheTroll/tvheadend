/*
 *  tvheadend - CSA wrapper
 *  Copyright (C) 2013 Adam Sutton
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TVH_CSA_H__
#define __TVH_CSA_H__

struct mpegts_service;
struct elementary_stream;

#include <stdint.h>
#include <pthread.h>
#include "build.h"
#if ENABLE_DVBCSA
#include <dvbcsa/dvbcsa.h>
#include <semaphore.h>
#include <fcntl.h>
struct mpegts_service;
#endif

#define MAX_CSA_CLUSTERS 64

typedef struct tvhcsa
{

  /**
   * CSA
   */
  int      csa_type;   /*< see DESCRAMBLER_* defines */
  int      csa_keylen;
  void   (*csa_descramble)
              ( struct tvhcsa *csa, struct mpegts_service *s,
                const uint8_t *tsb, int len );
  void   (*csa_flush)
              ( struct tvhcsa *csa, struct mpegts_service *s );

  int      csa_cluster_size;
  uint32_t cluster_rptr;
  uint32_t cluster_wptr;
  struct {
    int      csa_fill;
    uint8_t *csa_tsbcluster;
    uint8_t ready;
  } cluster[MAX_CSA_CLUSTERS];

  pthread_t nc_flush_task_id;
  uint8_t nc_flush_task_running;
  sem_t nc_flush_sem;

#if ENABLE_DVBCSA
  struct dvbcsa_bs_batch_s *csa_tsbbatch_even;
  struct dvbcsa_bs_batch_s *csa_tsbbatch_odd;
  int csa_fill_even;
  int csa_fill_odd;

  struct dvbcsa_bs_key_s *csa_key_even;
  struct dvbcsa_bs_key_s *csa_key_odd;

  struct mpegts_service *service;
  char even[8];
  char odd[8];
#endif
  void *csa_priv;

} tvhcsa_t;

#if ENABLE_TVHCSA

int  tvhcsa_set_type( tvhcsa_t *csa, int type );

void tvhcsa_set_key_even( tvhcsa_t *csa, const uint8_t *even );
void tvhcsa_set_key_odd ( tvhcsa_t *csa, const uint8_t *odd );

void tvhcsa_init    ( tvhcsa_t *csa , struct mpegts_service *service );
void tvhcsa_destroy ( tvhcsa_t *csa , struct mpegts_service *service );

#else

static inline int tvhcsa_set_type( tvhcsa_t *csa, int type ) { return -1; }

static inline void tvhcsa_set_key_even( tvhcsa_t *csa, const uint8_t *even ) { };
static inline void tvhcsa_set_key_odd ( tvhcsa_t *csa, const uint8_t *odd ) { };

static inline void tvhcsa_init ( tvhcsa_t *csa , struct mpegts_service *service ) { };
static inline void tvhcsa_destroy ( tvhcsa_t *csa , struct mpegts_service *service ) { };

#endif

#endif /* __TVH_CSA_H__ */
