#ifndef __TVH_NCSERVER_H__
#define __TVH_NCSERVER___

#define NC_CSA_CLUSTER_SIZE	2048
#define NC_CLEAR_CLUSTER_SIZE	256

int nc_init_service(tvhcsa_t *csa);
int nc_set_key(uint8_t is_even, tvhcsa_t* csa);
int nc_add_pid(int pid, tvhcsa_t* csa);
int nc_descramble(unsigned char* buffer, int size, tvhcsa_t* csa);
int nc_release_service(tvhcsa_t* csa);
void nc_log(tvhcsa_t *csa, const char* format, ...);
void nc_set_service_bad(tvhcsa_t *csa);

#endif
