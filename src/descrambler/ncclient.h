#define NC_CLUSTER_SIZE	512

int nc_set_key(int service, uint8_t is_even, char* key);
int nc_add_pid(int service, int pid);
int nc_descramble(int service, unsigned char* buffer, int size);

