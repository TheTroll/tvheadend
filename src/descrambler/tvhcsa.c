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

    ts_recv_packet2(s, csa->csa_tsbcluster, csa->csa_fill * 188);

    csa->csa_fill = 0;
  }
  else
  {
    if (nc_set_key(service_id16(s), 1, csa->even) || nc_set_key(service_id16(s), 0, csa->odd))
    {
       nc_log(service_id16(s), "set key failed, restart task\n");
       nc_release_service(service_id16(s));
    }
    else
    {
      // struct timeval stop, start;
      // gettimeofday(&start, NULL);

      if (nc_descramble(service_id16(s), csa->csa_tsbcluster, csa->csa_fill * 188) )
      {
        nc_log(service_id16(s), "decoding failed, try again..\n");
        nc_release_service(service_id16(s));
        nc_set_key(service_id16(s), 1, csa->even);
        nc_set_key(service_id16(s), 0, csa->odd);
        for (unsigned char* pkt = csa->csa_tsbcluster; pkt < (csa->csa_tsbcluster+csa->csa_fill*188); pkt += 188)
          nc_add_pid(service_id16(s), (pkt[1] & 0x1f)<<8 | (pkt[2] & 0xFF));

        if (nc_descramble(service_id16(s), csa->csa_tsbcluster, csa->csa_fill * 188))
        {
          nc_log(service_id16(s), "decoding failed again, dropping packets..\n");
          nc_release_service(service_id16(s));
        }
        else
        {
          // gettimeofday(&stop, NULL);
          // nc_log(service_id16(s), "took %lu ms for %d bytes", (stop.tv_sec*1000 +stop.tv_usec/1000) - (start.tv_sec*1000 + start.tv_usec/1000), csa->csa_fill * 188);

          ts_recv_packet2(s, csa->csa_tsbcluster, csa->csa_fill * 188);
        }
      }
      else
      {
        // gettimeofday(&stop, NULL);
        // nc_log(service_id16(s), "took %lu ms for %d bytes", (stop.tv_sec*1000 +stop.tv_usec/1000) - (start.tv_sec*1000 + start.tv_usec/1000), csa->csa_fill * 188);

        ts_recv_packet2(s, csa->csa_tsbcluster, csa->csa_fill * 188);
      }
    }
    csa->csa_fill = 0;
  }
#endif
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

    assert(csa->csa_fill >= 0 && csa->csa_fill < csa->csa_cluster_size);

    for ( ; tsb < tsb_end; tsb += 188) {

     pkt = csa->csa_tsbcluster + csa->csa_fill * 188;
     memcpy(pkt, tsb, 188);
     csa->csa_fill++;

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

     if(csa->csa_fill && csa->csa_fill == csa->csa_cluster_size)
       tvhcsa_csa_cbc_flush(csa, s);

    }
  }
  else
  {
    uint8_t *pkt;

    assert(csa->csa_fill >= 0 && csa->csa_fill < NC_CLUSTER_SIZE);

    for ( ; tsb < tsb_end; tsb += 188) {
      pkt = csa->csa_tsbcluster + csa->csa_fill * 188;
      memcpy(pkt, tsb, 188);
      csa->csa_fill++;

      nc_add_pid(service_id16(s), (pkt[1] & 0x1f)<<8 | (pkt[2] & 0xFF));

      if(csa->csa_fill && csa->csa_fill == NC_CLUSTER_SIZE)
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

#if ENABLE_DVBCSA
  int csa_cluster_size;

  if (csa->service && csa->service->ncserver)
    csa_cluster_size = NC_CLUSTER_SIZE;
  else
    csa_cluster_size = dvbcsa_bs_batch_size();
#endif

 switch (type) {
  case DESCRAMBLER_CSA_CBC:
    csa->csa_descramble    = tvhcsa_csa_cbc_descramble;
    csa->csa_flush         = tvhcsa_csa_cbc_flush;
    csa->csa_keylen        = 8;
#if ENABLE_DVBCSA
    csa->csa_cluster_size  = csa_cluster_size;
#endif
    /* Note: the optimized routines might read memory after last TS packet */
    /*       allocate safe memory and fill it with zeros */
    csa->csa_tsbcluster    = malloc((csa_cluster_size + 1) * 188);
    memset(csa->csa_tsbcluster + csa_cluster_size * 188, 0, 188);
#if ENABLE_DVBCSA
    csa->csa_tsbbatch_even = malloc((csa_cluster_size + 1) *
                                    sizeof(struct dvbcsa_bs_batch_s));
    csa->csa_tsbbatch_odd  = malloc((csa_cluster_size + 1) *
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
    memcpy(csa->even, even, 8);
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
    memcpy(csa->odd, odd, 8);
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
tvhcsa_init ( tvhcsa_t *csa , service_t *service )
{
  csa->csa_type          = 0;
  csa->csa_keylen        = 0;
  csa->service            = service;
}

void
tvhcsa_destroy ( tvhcsa_t *csa , service_t *service )
{
  if (service && service_id16(service))
    nc_release_service(service_id16(service));

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
  if (csa->csa_tsbcluster)
    free(csa->csa_tsbcluster);
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
