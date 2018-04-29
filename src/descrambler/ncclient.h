#ifndef __TVH_NCSERVER_H__
#define __TVH_NCSERVER___

#define NC_CLUSTER_SIZE	2048

int nc_set_key(int service, uint8_t is_even, char* key);
int nc_add_pid(int service, int pid);
int nc_descramble(int service, unsigned char* buffer, int size);
int nc_release_service(int service);
void nc_log(int srvid, const char* format, ...);

#endif
