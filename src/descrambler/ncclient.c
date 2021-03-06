#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"

#include "settings.h"
#include "input.h"
#include "subscriptions.h"
#include "channels.h"
#include "ncclient.h"

int nc_verbose = 0;

#define NC_TIMEOUT_S		2
#define NC_IP			config.ncserver_ip
#define NC_PORT			config.ncserver_port

enum nc_query_type
{
	NC_QUERY_TYPE_INIT_SERVICE =	(1<<0),
	NC_QUERY_TYPE_ADD_PID =		(1<<1),
	NC_QUERY_TYPE_SET_EVEN_KEY =	(1<<2),
	NC_QUERY_TYPE_SET_ODD_KEY =	(1<<3),
	NC_QUERY_TYPE_DESCRAMBLE =	(1<<4),
	NC_QUERY_TYPE_RELEASE =		(1<<5),
};

enum nc_query_status
{
	NC_QUERY_STATUS_OK = 0,
	NC_QUERY_STATUS_ERROR = 1

};

struct nc_query_in
{
	enum nc_query_type type;

	uint32_t data_size;
	char* data;

};

struct nc_query_out
{
	enum nc_query_type type;
	enum nc_query_status status;

	uint32_t data_size;
	char* data;
};

static uint32_t nc_query(struct nc_query_in* in, struct nc_query_out* out, tvhcsa_t *csa);
static const char* nc_get_srv_name(tvhcsa_t* csa);

/***********************************************/
/***********************************************/
int nc_init_service(tvhcsa_t *csa)
{
	struct timeval tv_timeout;
	tv_timeout.tv_sec = NC_TIMEOUT_S;
	tv_timeout.tv_usec = 0;

	if (!csa || !csa->service)
	{
		nc_log(NULL, "nc_init_service failed, NULL pointer\n");
		goto NC_INIT_SERVICE_FAIL;
	}

	if (csa->nc.init_done)
		return 0;

	// Find service in tasks
	if (!NC_IP || !strlen(NC_IP) || !NC_PORT)
	{
		nc_log(csa, "nc_init_service failed, no NC server set\n");
		goto NC_INIT_SERVICE_FAIL;
	}

	strncpy(csa->nc.server_ip, NC_IP, 15);
	csa->nc.server_port = NC_PORT;

	// Socket
	csa->nc.socket_fd=socket(AF_INET,SOCK_STREAM,0);
	if (csa->nc.socket_fd == -1)
	{
		nc_log(csa, "nc_init_service failed, cannot open socket\n");
		goto NC_INIT_SERVICE_FAIL;
	}

	// Set Keep alive
	int optval = 1;
	socklen_t optlen = sizeof(optval);
	if(setsockopt(csa->nc.socket_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0)
	{
		nc_log(csa, "could not set KEEPALIVE option (%s)\n", strerror(errno));
		goto NC_INIT_SERVICE_FAIL;
	}

	// Set non blocking
	int opts = fcntl(csa->nc.socket_fd,F_GETFL);
	if (opts < 0)
	{
		nc_log(csa, "could not set NONBLOCK option (%s)\n", strerror(errno));
		goto NC_INIT_SERVICE_FAIL;
	}
	else
	{
		opts = (opts | O_NONBLOCK);
		if (fcntl(csa->nc.socket_fd,F_SETFL,opts) < 0)
		{
			nc_log(csa, "could not set NONBLOCK option (%s)\n", strerror(errno));
			goto NC_INIT_SERVICE_FAIL;
		}
	}

	// Set the Server address
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=inet_addr(NC_IP);
	servaddr.sin_port=htons(NC_PORT);

	// Now connect
	int connect_ret = connect(csa->nc.socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (connect_ret < 0)
	{
		if (errno == EINPROGRESS)
		{
			fd_set wset;
			FD_ZERO(&wset);
			FD_SET(csa->nc.socket_fd, &wset);

			int select_ret = select(csa->nc.socket_fd+1, NULL, &wset, NULL, &tv_timeout);
			if (select_ret == 0)
			{
				nc_log(csa, "select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
				goto NC_INIT_SERVICE_FAIL;
			}
			if (FD_ISSET(csa->nc.socket_fd, &wset))
			{
				int error;
				unsigned int len = sizeof(error);
				if (getsockopt(csa->nc.socket_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error)
				{
					nc_log(csa, "select error (%s), closing socket\n", strerror(errno));
					goto NC_INIT_SERVICE_FAIL;
				}
				else
				{
					struct nc_query_in query_in = {0, };
					struct nc_query_out query_out = {0, };
					char service_str[5];

                                        //                                         -                                       sprintf(service_str, "%04X", service);
					// Set service remotely
					query_in.type = NC_QUERY_TYPE_INIT_SERVICE;
					query_in.data = (char*) nc_get_srv_name(csa);
					if (query_in.data)
						query_in.data_size = strlen(query_in.data)+1;
					else
					{
						sprintf(service_str, "%04X", service_id16(csa->service));
						query_in.data = service_str;
						query_in.data_size = 5;
					}

					// Go 
					if (nc_query(&query_in, &query_out, csa))
					{
						nc_log(csa, "query failed to init service\n");;
						goto NC_INIT_SERVICE_FAIL;
					}
				}
			}
			else
			{
				nc_log(csa, "select error (%s), closing socket\n", strerror(errno));
				goto NC_INIT_SERVICE_FAIL;
			}
		}
		else
		{
			nc_log(csa, "connect error (%s), closing socket\n", strerror(errno));
			goto NC_INIT_SERVICE_FAIL;
		}
	}

	csa->nc.nb_pids = 0;
	csa->nc.init_done = 1;

	nc_log(csa, "connected to server\n");

	return 0;

NC_INIT_SERVICE_FAIL:

	if (csa->nc.socket_fd != -1)
	{
		close(csa->nc.socket_fd);
		csa->nc.socket_fd = -1;
	}


	// Bad service
	nc_set_service_bad(csa);

	return -1;
}

int nc_set_key(uint8_t is_even, tvhcsa_t *csa)
{
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };
	char* key;
	uint8_t* set;

	if (!csa || !csa->service)
		return 1;

	if (!csa->nc.init_done)
	{
		nc_log(csa, "nc_set_key failed, ncserver not initialized\n");
		return 1;
	}

	if (is_even)
	{
		key = csa->nc.even;
		set = &csa->nc.even_available;
		query_in.type = NC_QUERY_TYPE_SET_EVEN_KEY;
	}
	else
	{
		key = csa->nc.odd;
		set = &csa->nc.odd_available;
		query_in.type = NC_QUERY_TYPE_SET_ODD_KEY;
	}

	// Set pid remotely
	query_in.data = key;
	query_in.data_size = 8;
	// Go 
	if (nc_query(&query_in, &query_out, csa))
	{
		nc_log(csa, "failed to set %s key\n", is_even?"EVEN":"ODD");
		return 1;
	}

	nc_log(csa, "set %s key [%02X %02X %02X %02X %02X %02X %02X %02X]\n", is_even?"EVEN":"ODD ",
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
	*set = 0;

	return 0;
}

int nc_add_pid(int pid, tvhcsa_t *csa)
{
	int pid_idx;
	if (!csa || !csa->service)
		return 1;

	if (!csa->nc.init_done)
	{
		nc_log(csa, "nc_add_pid failed, ncserver not initialized\n");
		return 1;
	}

	// Check if it was already added
	for (pid_idx=0; pid_idx<csa->nc.nb_pids; pid_idx++)
	{
		if (csa->nc.pid[pid_idx] == pid)
			return 0;
	}

	// Add it
	if (csa->nc.nb_pids < NC_MAX_PIDS)
	{
		struct nc_query_in query_in = {0, };
		struct nc_query_out query_out = {0, };
		char pid_str[5];

		csa->nc.pid[csa->nc.nb_pids] = pid;
		csa->nc.nb_pids++;

		// Set pid remotely
		query_in.type = NC_QUERY_TYPE_ADD_PID;
		sprintf(pid_str, "%04X", pid);
		query_in.data = pid_str;
		query_in.data_size = 5;

		// Go 
		if (nc_query(&query_in, &query_out, csa))
		{
			csa->nc.nb_pids--;
			nc_log(csa, "query failed to add pid 0x%x\n", pid);
			return 1;
		}

		nc_log(csa, "added pid 0x%x\n", pid);

		return 0;	
	}

	// No more room
	nc_log(csa, "no more room to add pid 0x%x\n", pid);
	return 1;
}


int nc_descramble(unsigned char* buffer, int size, tvhcsa_t *csa)
{
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };
	if (!csa || !csa->service)
		return 1;

	if (!size || !buffer)
		return 0;

	if (!csa->nc.init_done)
	{
		nc_log(csa, "nc_descramble failed, ncserver not initialized\n");
		return 1;
	}

	// Descramble
	query_in.type = NC_QUERY_TYPE_DESCRAMBLE;
	query_in.data = (char*) buffer;
	query_out.data = (char*) buffer;
	query_in.data_size = size;
	// Go 
	if (nc_query(&query_in, &query_out, csa))
		return 1;

	return 0;
}

int nc_release_service(tvhcsa_t *csa)
{
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };
	if (!csa || !csa->service)
		return 1;

	if (!csa->nc.init_done)
	{
		return 0;
	}

	if (nc_verbose)
		nc_log(csa, "releasing service\n");

	// Release remote
	query_in.type = NC_QUERY_TYPE_RELEASE;

	// Go 
	if (nc_query(&query_in, &query_out, csa))
		nc_log(csa,"release service failed\n");

	close(csa->nc.socket_fd);

	// Remove locally
	memset(&csa->nc, 0, sizeof(csa->nc));

	nc_log(csa, "disconnected from server\n");

	return 1;
}

static const char* nc_get_srv_name(tvhcsa_t* csa)
{
	if (!csa || !csa->service)
		return NULL;
	if (LIST_FIRST(&csa->service->s_channels))
	{
		idnode_list_mapping_t* first_chan = LIST_FIRST(&csa->service->s_channels);
		return channel_get_name((channel_t *) first_chan->ilm_in2, channel_blank_name);
	}
	else if (csa->service->s_dvb_svcname)
		return  csa->service->s_dvb_svcname;
	else if (csa->service->s_nicename)
		return csa->service->s_nicename;
	else
		return NULL;
}

void nc_log(tvhcsa_t *csa, const char* format, ...)
{
	char t[128], path[512];
	struct tm tm;
	struct timeval time;
	FILE *file = NULL;

	hts_settings_buildpath(path, sizeof(path), "nc.log");

	file=fopen(path, "a");
	if (file)
	{
		va_list argptr;
		va_start(argptr, format);

		gettimeofday(&time, NULL);
		localtime_r(&time.tv_sec, &tm);
		strftime(t, sizeof(t), "%F %T", &tm);

		fprintf(file, "[%s] %-16s > ", t, nc_get_srv_name(csa));
		vfprintf(file, format, argptr);
		va_end(argptr);

		fclose(file);
	}
}

//////////////////////////////////////////////////////////////////

/* Frame :
 *
 * IN/OUT: HHHH|XXXXXXXX|Data
 * HHHH: 4 bytes command/status
 * XXXXXXXX: 8 bytes data size
 * Data
 *
 * Header size : 16 bytes
 * */


#define NC_HEADER_SIZE 12

static uint32_t nc_query(struct nc_query_in* in, struct nc_query_out* out, tvhcsa_t *csa)
{
	const char* cmd;
	int read_size, sent_size;
	struct timeval tv_timeout;
	tv_timeout.tv_sec = NC_TIMEOUT_S;
	tv_timeout.tv_usec = 0;
	char header[NC_HEADER_SIZE+1];
	char status_buf[5];
	char datasize_buf[9];

	if (!csa->nc.socket_fd)
		return 1;

	// Now We can now talk to server
	switch (in->type)
	{
		case NC_QUERY_TYPE_INIT_SERVICE:
			cmd = "INIT";
			break;
		case NC_QUERY_TYPE_ADD_PID:
			cmd = "SPID";
			break;
		case NC_QUERY_TYPE_SET_EVEN_KEY:
			cmd = "KEVN";
			break;
		case NC_QUERY_TYPE_SET_ODD_KEY:
			cmd = "KODD";
			break;
		case NC_QUERY_TYPE_DESCRAMBLE:
			cmd = "DESC";
			break;
		case NC_QUERY_TYPE_RELEASE:
			cmd = "RELS";
			break;
		default:
			return 1;
	}

	sprintf(header, "%s%08X", cmd, in->data_size);

	// Send data
	fd_set write_fd;
	FD_ZERO(&write_fd);
	FD_SET(csa->nc.socket_fd, &write_fd);

	int t = select(csa->nc.socket_fd+1, NULL, &write_fd, NULL, &tv_timeout);
	if (t <= 0)
	{
		nc_log(csa, "write select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
		goto NC_QUERY_ERROR;
	}

	if (!NC_IP || !strlen(NC_IP) || !NC_PORT)
	{
		nc_log(csa, "server not set\n");
		goto NC_QUERY_ERROR;
	}

	// Set the Server address
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=inet_addr(NC_IP);
	servaddr.sin_port=htons(NC_PORT);

	if (nc_verbose)
		nc_log(csa, "sending header [%s]\n", header);

	// Send header
	sent_size=sendto(csa->nc.socket_fd, header, NC_HEADER_SIZE, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (sent_size != NC_HEADER_SIZE)
	{
		nc_log(csa, "error sending to server (%s), closing socket\n", strerror(errno));
		goto NC_QUERY_ERROR;
	}

	// Send data
	if (in->data_size)
	{
		int total_sent_size = 0;

		while (total_sent_size < in->data_size)
		{
			// Send data
			fd_set write_fd;
			FD_ZERO(&write_fd);
			FD_SET(csa->nc.socket_fd, &write_fd);

			int t = select(csa->nc.socket_fd+1, NULL, &write_fd, NULL, &tv_timeout);
			if (t <= 0)
			{
				nc_log(csa, "write select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
				goto NC_QUERY_ERROR;
			}

			sent_size=sendto(csa->nc.socket_fd, in->data+total_sent_size, in->data_size-total_sent_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
			if (sent_size <= 0)
			{
				nc_log(csa, "error sending to server (%s), closing socket\n", strerror(errno));
				goto NC_QUERY_ERROR;
			}

			total_sent_size += sent_size;
		}
	}

	// Wait for an answer from server
	fd_set read_fd;
	FD_ZERO(&read_fd);
	FD_SET(csa->nc.socket_fd, &read_fd);

	t = select(csa->nc.socket_fd+1, &read_fd, NULL, NULL, &tv_timeout);
	if (t < 0)
	{
		nc_log(csa, "read select error (%s), closing socket\n", strerror(errno));
		goto NC_QUERY_ERROR;
	}
	else if (t == 0)
	{
		nc_log(csa, "read select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
		goto NC_QUERY_ERROR;
	}

	// First get header
	read_size=recvfrom(csa->nc.socket_fd, header, NC_HEADER_SIZE, 0, NULL, NULL);
	if (read_size <= 0)
	{
		nc_log(csa, "error receiving from server (%s), closing socket\n", strerror(errno));
		goto NC_QUERY_ERROR;
	}

	if (read_size != NC_HEADER_SIZE)
	{
		nc_log(csa, "invalid header size %d\n", read_size);
		goto NC_QUERY_ERROR;
	}

	if (nc_verbose)
		nc_log(csa, "received header [%s]\n", header);

	// Get values
	memcpy(status_buf, header, 4);
	status_buf[4] = 0;
	memcpy(datasize_buf, header+4, 8);
	datasize_buf[8] = 0;
	sscanf(datasize_buf, "%X", &out->data_size);

	if (!strcmp("GOOD", status_buf))
		out->status = NC_QUERY_STATUS_OK;
	else
	{
		out->status = NC_QUERY_STATUS_ERROR;
		goto NC_QUERY_ERROR;
	}

	// Get data
	if (out->data_size)
	{
		int read_data = 0;

		while (read_data < out->data_size)
		{
			t = select(csa->nc.socket_fd+1, &read_fd, NULL, NULL, &tv_timeout);
			if (t < 0)
			{
				nc_log(csa, "read select error (%s), closing socket\n", strerror(errno));
				goto NC_QUERY_ERROR;
			}
			else if (t == 0)
			{
				nc_log(csa, "read select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
				goto NC_QUERY_ERROR;
			}

			int data_read_size = recvfrom(csa->nc.socket_fd, out->data+read_data, out->data_size-read_data, 0, NULL, NULL);
			if (data_read_size == 0)
			{
				nc_log(csa, "server disconnected\n");
				goto NC_QUERY_ERROR;
			}
			else if (data_read_size == -1)
			{
				nc_log(csa, "server error\n");
				goto NC_QUERY_ERROR;
			}
			read_data+=data_read_size;
		}
	}

	return 0 ;

NC_QUERY_ERROR:

	// Bad service
	nc_set_service_bad(csa);

	return 1;

}

void nc_set_service_bad(tvhcsa_t *csa)
{
	th_subscription_t *ths;
	uint8_t set_bad = 0;

	if (!csa || !csa->service)
		return;

	// Don't set it twice
	LIST_FOREACH(ths, &csa->service->s_subscriptions, ths_service_link)
		if (ths->ths_state != SUBSCRIPTION_BAD_SERVICE)
		{
			set_bad = 1;
			break;
		}

	if (set_bad)
	{
		// Bad service
		nc_log(csa, "setting service as BAD\n");
		LIST_FOREACH(ths, &csa->service->s_subscriptions, ths_service_link)
		{
			atomic_set(&ths->ths_testing_error, SM_CODE_NO_SOURCE);
			atomic_set(&ths->ths_state, SUBSCRIPTION_BAD_SERVICE);
		}
	}
}

