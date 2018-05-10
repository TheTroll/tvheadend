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

#include "tvhcsa.h"
#include "input.h"
#include "input/mpegts/tsdemux.h"

#include "descrambler/algo/libaesdec.h"
#include "descrambler/algo/libaes128dec.h"
#include "descrambler/algo/libdesdec.h"

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "ncclient.h"

static void
tvhcsa_empty_flush
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
  /* empty - no queue */
}

static void
tvhcsa_aes_ecb_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int len )
{
  const uint8_t *tsb2, *end2;

  for (tsb2 = tsb, end2 = tsb + len; tsb2 < end2; tsb2 += 188)
    aes_decrypt_packet(csa->csa_priv, tsb2);
  ts_recv_packet2(s, tsb, len);
}

static void
tvhcsa_aes128_ecb_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int len )
{
  const uint8_t *tsb2, *end2;

  for (tsb2 = tsb, end2 = tsb + len; tsb2 < end2; tsb2 += 188)
    aes128_decrypt_packet(csa->csa_priv, tsb2);
  ts_recv_packet2(s, tsb, len);
}

static void
tvhcsa_des_ncb_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int len )
{
  const uint8_t *tsb2, *end2;

  for (tsb2 = tsb, end2 = tsb + len; tsb2 < end2; tsb2 += 188)
    des_decrypt_packet(csa->csa_priv, tsb2);
  ts_recv_packet2(s, tsb, len);
}

static void
tvhcsa_csa_cbc_flush
  ( tvhcsa_t *csa, struct mpegts_service *s )
{
#if ENABLE_DVBCSA
  if (!s->ncserver)
  {
    if(csa->csa_fill_even) {
      csa->csa_tsbbatch_even[csa->csa_fill_even].data = NULL;
      dvbcsa_bs_decrypt(csa->csa_key_even, csa->csa_tsbbatch_even, 184);
      csa->csa_fill_even = 0;
    }
    if(csa->csa_fill_odd) {
      csa->csa_tsbbatch_odd[csa->csa_fill_odd].data = NULL;
      dvbcsa_bs_decrypt(csa->csa_key_odd, csa->csa_tsbbatch_odd, 184);
      csa->csa_fill_odd = 0;
    }

    ts_recv_packet2(s, csa->cluster[0].csa_tsbcluster, csa->cluster[0].csa_fill * 188);

    csa->cluster[0].csa_fill = 0;
  }
  else
  {
    th_subscription_t *ths;
    LIST_FOREACH(ths, &s->s_subscriptions, ths_service_link)
            if (ths->ths_state == SUBSCRIPTION_BAD_SERVICE)
                    return;
    if (csa->cluster[csa->cluster_wptr].csa_fill || csa->cluster[csa->cluster_wptr].clear_fill)
    {
      csa->cluster[csa->cluster_wptr].ready = 1;
      csa->cluster_wptr = (csa->cluster_wptr+1) % MAX_CSA_CLUSTERS;
      sem_post(&csa->nc.flush_sem);
    }
  }
#endif
}

static void *
nc_flush ( void *p )
{
  tvhcsa_t *csa = p;
  struct mpegts_service* s = csa->service;

  nc_log(service_id16(s), "CSA thread started\n");

  while (csa->nc.flush_task_running)
  {
    int level = (csa->cluster_wptr >= csa->cluster_rptr)?(csa->cluster_wptr - csa->cluster_rptr):(MAX_CSA_CLUSTERS+csa->cluster_wptr - csa->cluster_rptr);
    if (level >= MAX_CSA_CLUSTERS/2)
	    nc_log(service_id16(s), "fifo level is high  %d/%d\n", level, MAX_CSA_CLUSTERS);

    // Wait for semphore
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
     nc_log(service_id16(s), "failed getting time for sem_wait\n");
     break;
    }

    if (level < 1)
      ts.tv_sec+=10;

    sem_timedwait(&csa->nc.flush_sem, &ts);

    if (!csa->nc.flush_task_running)
      break;

    // Now check if we have a packet ready
    if (csa->cluster[csa->cluster_rptr].ready)
    {
      uint8_t has_odd, has_even;

      // nc_log(service_id16(s), "CSA=%d, CLEAR=%d\n", csa->cluster[csa->cluster_rptr].csa_fill, csa->cluster[csa->cluster_rptr].clear_fill);

      // Add crypted pids and get current key parity
      has_odd = has_even = 0;
      for (unsigned char* pkt=csa->cluster[csa->cluster_rptr].csa_tsbcluster; pkt<csa->cluster[csa->cluster_rptr].csa_tsbcluster + csa->cluster[csa->cluster_rptr].csa_fill * 188; pkt += 188)
      {
        if ((pkt[3]&0xc0) == 0xc0)
          has_odd = 1;
        if ((pkt[3]&0xc0) == 0x80)
          has_even = 1;

        if (nc_add_pid((pkt[1] & 0x1f)<<8 | (pkt[2] & 0xFF), csa))
        {
          nc_log(service_id16(s), "add pid failed\n");
          break;
        }
      }

      // Make sure we won't set the key too early (and break old packets)
      if (!has_odd || !csa->nc.odd_set)
      {
        if (nc_set_key(0, csa->nc.odd, csa))
        {
          nc_log(service_id16(s), "set ODD key failed\n");
          break;
        }
        csa->nc.odd_set = 1;
      } 
      if (!has_even || !csa->nc.even_set)
      {
        if (nc_set_key(1, csa->nc.even, csa))
        {
          nc_log(service_id16(s), "set EVEN key failed\n");
          break;
        }
        csa->nc.even_set = 1;
      } 

      // struct timeval stop, start;
      // gettimeofday(&start, NULL);

      if (csa->cluster[csa->cluster_rptr].csa_fill)
      {

        if (nc_descramble(csa->cluster[csa->cluster_rptr].csa_tsbcluster, csa->cluster[csa->cluster_rptr].csa_fill * 188, csa))
        {
            nc_log(service_id16(s), "decoding failed, dropping packets..\n");
            break;
        }

        // gettimeofday(&stop, NULL);
        // nc_log(service_id16(s), "took %lu ms for %d bytes", (stop.tv_sec*1000 +stop.tv_usec/1000) - (start.tv_sec*1000 + start.tv_usec/1000), csa->csa_fill * 188);

        if (!csa->nc.flush_task_running)
          break;

	pthread_mutex_lock(&s->s_stream_mutex);
        if (csa->cluster[csa->cluster_rptr].csa_fill)
          ts_recv_packet2(s, csa->cluster[csa->cluster_rptr].csa_tsbcluster, csa->cluster[csa->cluster_rptr].csa_fill * 188);
        if (csa->cluster[csa->cluster_rptr].clear_fill)
          ts_recv_packet2(s, csa->cluster[csa->cluster_rptr].clear_tsbcluster, csa->cluster[csa->cluster_rptr].clear_fill * 188);
	pthread_mutex_unlock(&s->s_stream_mutex);
      }
    } 

    csa->cluster[csa->cluster_rptr].csa_fill = 0;
    csa->cluster[csa->cluster_rptr].clear_fill = 0;
    csa->cluster[csa->cluster_rptr].ready = 0;
    csa->cluster_rptr = (csa->cluster_rptr+1) % MAX_CSA_CLUSTERS;
  }

  nc_release_service(csa);
  nc_log(service_id16(s), "CSA thread exits\n");

  
  if (csa->nc.flush_task_running)
  {
    csa->nc.flush_task_running = 0;
    nc_log(service_id16(s), "setting service as BAD\n");
    th_subscription_t *ths;
    LIST_FOREACH(ths, &s->s_subscriptions, ths_service_link)
    {
      atomic_set(&ths->ths_testing_error, SM_CODE_NO_SOURCE);
      atomic_set(&ths->ths_state, SUBSCRIPTION_BAD_SERVICE);
    }
  }

  return NULL;
}

static void
tvhcsa_csa_cbc_descramble
  ( tvhcsa_t *csa, struct mpegts_service *s, const uint8_t *tsb, int tsb_len )
{
  const uint8_t *tsb_end = tsb + tsb_len;

#if ENABLE_DVBCSA
  if (!s->ncserver)
  {
    uint8_t *pkt;
    int ev_od;
    int len;
    int offset;
    int n;

    if (csa->cluster[0].csa_fill > csa->csa_cluster_size)
    {
      csa->cluster[0].csa_fill = 0;
      return;
    }


    for ( ; tsb < tsb_end; tsb += 188) {

     pkt = csa->cluster[0].csa_tsbcluster + csa->cluster[0].csa_fill * 188;
     memcpy(pkt, tsb, 188);
     csa->cluster[0].csa_fill++;

     do { // handle this packet
       if((pkt[3] & 0x80) == 0) // clear or reserved (0x40)
         break;
       ev_od = pkt[3] & 0x40;
       pkt[3] &= 0x3f;  // consider it decrypted now
       if(pkt[3] & 0x20) { // incomplete packet
         offset = 4 + pkt[4] + 1;
         len = 188 - offset;
         n = len >> 3;
         // FIXME: //residue = len - (n << 3);
         if(n == 0) { // decrypted==encrypted!
           break; // this doesn't need more processing
         }
       } else {
         len = 184;
         offset = 4;
         // FIXME: //n = 23;
         // FIXME: //residue = 0;
       }
       if(ev_od == 0) {
         csa->csa_tsbbatch_even[csa->csa_fill_even].data = pkt + offset;
         csa->csa_tsbbatch_even[csa->csa_fill_even].len = len;
         csa->csa_fill_even++;
       } else {
         csa->csa_tsbbatch_odd[csa->csa_fill_odd].data = pkt + offset;
         csa->csa_tsbbatch_odd[csa->csa_fill_odd].len = len;
         csa->csa_fill_odd++;
       }
     } while(0);

     if(csa->cluster[0].csa_fill && csa->cluster[0].csa_fill == csa->csa_cluster_size)
       tvhcsa_csa_cbc_flush(csa, s);

    }
  }
  else
  {
    uint8_t *pkt;
    th_subscription_t *ths;

    LIST_FOREACH(ths, &s->s_subscriptions, ths_service_link)
            if (ths->ths_state == SUBSCRIPTION_BAD_SERVICE)
                    return;

    if (!csa->nc.flush_task_running)
      return;

    if (csa->cluster[csa->cluster_wptr].ready)
    {
      nc_log(service_id16(s), "cluster fifo full\n");
      return;
    }

    for ( ; tsb < tsb_end; tsb += 188) {
      int i, pid = (tsb[1] & 0x1f)<<8 | (tsb[2] & 0xFF);

      // Mark crypted PIDS
      if ((tsb[3] & 0x80) && csa->crypted_pid_count < 64)
      {
        for (i=0; i<csa->crypted_pid_count; i++)
          if (csa->crypted_pid[i] == pid)
            break;
        if (i == csa->crypted_pid_count)
        {
          csa->crypted_pid[csa->crypted_pid_count] = pid;
          csa->crypted_pid_count++;
        }
      }

      // Is PID crypted ?
      for (i=0; i<csa->crypted_pid_count; i++)
      {
        if (csa->crypted_pid[i] == pid)
        {
          pkt = csa->cluster[csa->cluster_wptr].csa_tsbcluster + csa->cluster[csa->cluster_wptr].csa_fill * 188;
          memcpy(pkt, tsb, 188);
          csa->cluster[csa->cluster_wptr].csa_fill++;
//        nc_log(service_id16(s), "Adding crypted PID 0x%x 0x%02X\n", (pkt[1] & 0x1f)<<8 | (pkt[2] & 0xFF), tsb[3]);
          break;
        }
      }

      // Clear PID ?
      if (i == csa->crypted_pid_count)
      {
        pkt = csa->cluster[csa->cluster_wptr].clear_tsbcluster + csa->cluster[csa->cluster_wptr].clear_fill * 188;
        memcpy(pkt, tsb, 188);
        csa->cluster[csa->cluster_wptr].clear_fill++;
//        nc_log(service_id16(s), "Adding clear PID 0x%x 0x%02X\n", (pkt[1] & 0x1f)<<8 | (pkt[2] & 0xFF), tsb[3]);
      }

      if (csa->cluster[csa->cluster_wptr].csa_fill == NC_CSA_CLUSTER_SIZE || csa->cluster[csa->cluster_wptr].clear_fill == NC_CLEAR_CLUSTER_SIZE)
        tvhcsa_csa_cbc_flush(csa, s);
    }
  }
#endif
}

int
tvhcsa_set_type( tvhcsa_t *csa, int type )
{
  if (csa->csa_type == type)
    return 0;
  if (csa->csa_descramble)
    return -1;

 switch (type) {
  case DESCRAMBLER_CSA_CBC:
    csa->csa_descramble    = tvhcsa_csa_cbc_descramble;
    csa->csa_flush         = tvhcsa_csa_cbc_flush;
    csa->csa_keylen        = 8;
    /* Note: the optimized routines might read memory after last TS packet */
    /*       allocate safe memory and fill it with zeros */
    if (csa->service && csa->service->ncserver)
    {
      for (int cluster=0; cluster<MAX_CSA_CLUSTERS; cluster++) {
        csa->cluster[cluster].csa_tsbcluster    = malloc((NC_CSA_CLUSTER_SIZE + 1) * 188);
        csa->cluster[cluster].clear_tsbcluster    = malloc((NC_CLEAR_CLUSTER_SIZE + 1) * 188);
        memset(csa->cluster[cluster].csa_tsbcluster + NC_CSA_CLUSTER_SIZE * 188, 0, 188);
        memset(csa->cluster[cluster].clear_tsbcluster + NC_CLEAR_CLUSTER_SIZE * 188, 0, 188);
      }

    } else {
#if ENABLE_DVBCSA
      csa->csa_cluster_size = dvbcsa_bs_batch_size();
#else
      csa->csa_cluster_size = 0;
#endif
      csa->cluster[0].csa_tsbcluster    = malloc((dvbcsa_bs_batch_size() + 1) * 188);
      memset(csa->cluster[0].csa_tsbcluster + dvbcsa_bs_batch_size() * 188, 0, 188);
    }
#if ENABLE_DVBCSA
    csa->csa_tsbbatch_even = malloc((dvbcsa_bs_batch_size() + 1) *
                                    sizeof(struct dvbcsa_bs_batch_s));
    csa->csa_tsbbatch_odd  = malloc((dvbcsa_bs_batch_size() + 1) *
                                    sizeof(struct dvbcsa_bs_batch_s));
    csa->csa_key_even      = dvbcsa_bs_key_alloc();
    csa->csa_key_odd       = dvbcsa_bs_key_alloc();
#endif
    break;
  case DESCRAMBLER_DES_NCB:
    csa->csa_priv          = des_get_priv_struct();
    csa->csa_descramble    = tvhcsa_des_ncb_descramble;
    csa->csa_flush         = tvhcsa_empty_flush;
    csa->csa_keylen        = 8;
    break;
  case DESCRAMBLER_AES_ECB:
    csa->csa_priv          = aes_get_priv_struct();
    csa->csa_descramble    = tvhcsa_aes_ecb_descramble;
    csa->csa_flush         = tvhcsa_empty_flush;
    csa->csa_keylen        = 8;
    break;
  case DESCRAMBLER_AES128_ECB:
    csa->csa_priv          = aes128_get_priv_struct();
    csa->csa_descramble    = tvhcsa_aes128_ecb_descramble;
    csa->csa_flush         = tvhcsa_empty_flush;
    csa->csa_keylen        = 16;
    break;
  default:
    assert(0);
  }
  csa->csa_type = type;
  return 0;
}


void tvhcsa_set_key_even( tvhcsa_t *csa, const uint8_t *even )
{
  switch (csa->csa_type) {
  case DESCRAMBLER_CSA_CBC:
#if ENABLE_DVBCSA
    dvbcsa_bs_key_set(even, csa->csa_key_even);
    memcpy(csa->nc.even, even, 8);
#endif
    break;
  case DESCRAMBLER_DES_NCB:
    des_set_even_control_word(csa->csa_priv, even);
    break;
  case DESCRAMBLER_AES_ECB:
    aes_set_even_control_word(csa->csa_priv, even);
    break;
  case DESCRAMBLER_AES128_ECB:
    aes128_set_even_control_word(csa->csa_priv, even);
    break;
  default:
    assert(0);
  }
}

void tvhcsa_set_key_odd( tvhcsa_t *csa, const uint8_t *odd )
{
  assert(csa->csa_type);
  switch (csa->csa_type) {
  case DESCRAMBLER_CSA_CBC:
#if ENABLE_DVBCSA
    dvbcsa_bs_key_set(odd, csa->csa_key_odd);
    memcpy(csa->nc.odd, odd, 8);
#endif
    break;
  case DESCRAMBLER_DES_NCB:
    des_set_odd_control_word(csa->csa_priv, odd);
    break;
  case DESCRAMBLER_AES_ECB:
    aes_set_odd_control_word(csa->csa_priv, odd);
    break;
  case DESCRAMBLER_AES128_ECB:
    aes128_set_odd_control_word(csa->csa_priv, odd);
    break;
  default:
    assert(0);
  }
}

void
tvhcsa_init ( tvhcsa_t *csa , struct mpegts_service *service )
{
  csa->csa_type          = 0;
  csa->csa_keylen        = 0;
  csa->service           = service;

  if (service->ncserver)
  {
    // Spawn descrambling task
    csa->crypted_pid_count = 0;
    csa->cluster_rptr = 0;
    csa->cluster_wptr = 0;
    csa->nc.odd_set = csa->nc.even_set = 0;
    sem_init(&csa->nc.flush_sem, 0, 0);
    csa->nc.flush_task_running = 1;
    if (!nc_init_service(csa))
	    tvhthread_create(&csa->nc.flush_task_id, NULL, nc_flush, csa, "DVBCSA");
  }
}

void
tvhcsa_destroy ( tvhcsa_t *csa , struct mpegts_service *service )
{
#if ENABLE_DVBCSA
  if (csa->csa_key_odd)
    dvbcsa_bs_key_free(csa->csa_key_odd);
  if (csa->csa_key_even)
    dvbcsa_bs_key_free(csa->csa_key_even);
  if (csa->csa_tsbbatch_odd)
    free(csa->csa_tsbbatch_odd);
  if (csa->csa_tsbbatch_even)
    free(csa->csa_tsbbatch_even);
#endif
  if (service->ncserver)
  {
    // Spawn descrambling task
    csa->nc.flush_task_running = 0;
    sem_post(&csa->nc.flush_sem);
    pthread_join(csa->nc.flush_task_id, NULL);
    sem_destroy(&csa->nc.flush_sem);
  }


  for (int cluster = 0; cluster < MAX_CSA_CLUSTERS; cluster++)
  {
    if (csa->cluster[cluster].csa_tsbcluster)
      free(csa->cluster[cluster].csa_tsbcluster);
    if (csa->cluster[cluster].clear_tsbcluster)
      free(csa->cluster[cluster].clear_tsbcluster);
  }
  if (csa->csa_priv) {
    switch (csa->csa_type) {
    case DESCRAMBLER_CSA_CBC:
      break;
    case DESCRAMBLER_DES_NCB:
      des_free_priv_struct(csa->csa_priv);
      break;
    case DESCRAMBLER_AES_ECB:
      aes_free_priv_struct(csa->csa_priv);
      break;
    case DESCRAMBLER_AES128_ECB:
      aes128_free_priv_struct(csa->csa_priv);
      break;
    default:
      assert(0);
    }
  }
  memset(csa, 0, sizeof(*csa));
}
