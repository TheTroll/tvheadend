#ifndef __TVH_NCSERVER_H__
#define __TVH_NCSERVER___

#define NC_CLUSTER_SIZE	1024

int nc_set_key(struct mpegts_service *s, uint8_t is_even, char* key);
int nc_add_pid(struct mpegts_service *s, int pid);
int nc_dump_pids(struct mpegts_service *s);
int nc_descramble(struct mpegts_service *s, unsigned char* buffer, int size);
int nc_release_service(struct mpegts_service *s);
void nc_log(int srvid, const char* format, ...);

#endif
