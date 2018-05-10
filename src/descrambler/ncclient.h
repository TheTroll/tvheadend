#ifndef __TVH_NCSERVER_H__
#define __TVH_NCSERVER___

#define NC_CSA_CLUSTER_SIZE	1024
#define NC_CLEAR_CLUSTER_SIZE	128

int nc_init_service(tvhcsa_t *csa);
int nc_set_key(uint8_t is_even, tvhcsa_t* csa);
int nc_add_pid(int pid, tvhcsa_t* csa);
int nc_descramble(unsigned char* buffer, int size, tvhcsa_t* csa);
int nc_release_service(tvhcsa_t* csa);
void nc_log(int srvid, const char* format, ...);

#endif
