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
#include "ncclient.h"

int nc_verbose = 0;

#define NC_TIMEOUT_S		10
#define NC_MAX_TASKS		64
#define NC_MAX_PIDS		16
#define NC_IP			config.ncserver_ip
#define NC_PORT			config.ncserver_port
#define NC_MAX_MSG_SIZE		((256*1024))

enum nc_query_type
{
	NC_QUERY_TYPE_ADD_PID =		(1<<0),
	NC_QUERY_TYPE_SET_EVEN_KEY =	(1<<1),
	NC_QUERY_TYPE_SET_ODD_KEY =	(1<<2),
	NC_QUERY_TYPE_DESCRAMBLE =	(1<<3),
	NC_QUERY_TYPE_RELEASE =		(1<<4),
};

enum nc_query_status
{
	NC_QUERY_STATUS_OK = 0,
	NC_QUERY_STATUS_ERROR = 1

};

struct nc_query_in
{
	enum nc_query_type type;

	int service_id;
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

struct
{
	int service;

	char server_ip[16];
	int server_port;

	int socket_fd;
	int nb_pids;
	int pid[NC_MAX_PIDS];

	char even[8];
	char odd[8];

} nc_task[NC_MAX_TASKS];

static int get_task(int service);
static uint32_t nc_query(int task_idx, struct nc_query_in* in, struct nc_query_out* out);

/***********************************************/
/***********************************************/

int nc_set_key(int service, uint8_t is_even, char* key)
{
	int task_idx;
	char* existing_key;
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };

	// Get task
	task_idx = get_task(service);
	if (task_idx < 0)
		return 1;

	if (is_even)
	{
		existing_key = nc_task[task_idx].even;
		query_in.type = NC_QUERY_TYPE_SET_EVEN_KEY;
	}
	else
	{
		existing_key = nc_task[task_idx].odd;
		query_in.type = NC_QUERY_TYPE_SET_ODD_KEY;
	}

	if (!memcmp(existing_key, key, 8))
		return 0;

	// Set pid remotely
	query_in.service_id = service;
	query_in.data = key;
	query_in.data_size = 8;
	// Go 
	if (nc_query(task_idx, &query_in, &query_out))
	{
		nc_log(service, "faild to set %s key\n", is_even?"EVEN":"ODD");
		return 1;
	}

	memcpy(existing_key, key, 8);
	nc_log(service, "set %s key [%02X %02X %02X %02X %02X %02X %02X %02X]\n", is_even?"EVEN":"ODD ",
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);

	return 0;
}

int nc_add_pid(int service, int pid)
{
	int task_idx, pid_idx;

	// Get task
	task_idx = get_task(service);
	if (task_idx < 0)
		return 1;

	// Check if it was already added
	for (pid_idx=0; pid_idx<nc_task[task_idx].nb_pids; pid_idx++)
	{
		if (nc_task[task_idx].pid[pid_idx] == pid)
			return 0;
	}

	// Add it
	if (nc_task[task_idx].nb_pids < NC_MAX_PIDS)
	{
		struct nc_query_in query_in = {0, };
		struct nc_query_out query_out = {0, };
		char pid_str[5];

		nc_task[task_idx].pid[nc_task[task_idx].nb_pids] = pid;
		nc_task[task_idx].nb_pids++;

		// Set pid remotely
		query_in.type = NC_QUERY_TYPE_ADD_PID;
		query_in.service_id = service;
		sprintf(pid_str, "%04X", pid);
		query_in.data = pid_str;
		query_in.data_size = 5;

		// Go 
		if (nc_query(task_idx, &query_in, &query_out))
		{
			nc_task[task_idx].nb_pids--;
			nc_log(service, "query failed to add pid 0x%x\n", pid);
			return 1;
		}

		nc_log(service, "added pid 0x%x\n", pid);

		return 0;	
	}

	// No more room
	nc_log(service, "no more room to add pid 0x%x\n", pid);
	return 1;
}


int nc_descramble(int service, unsigned char* buffer, int size)
{
	int task_idx;
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };

	if (!size || !buffer)
		return 0;

	// Get task
	task_idx = get_task(service);
	if (task_idx < 0)
		return 1;

	// Descramble
	query_in.type = NC_QUERY_TYPE_DESCRAMBLE;
	query_in.service_id = service;
	query_in.data = (char*) buffer;
	query_out.data = (char*) buffer;
	query_in.data_size = size;
	// Go 
	if (nc_query(task_idx, &query_in, &query_out))
	{
		return 1;
	}

	return 0;
}

int nc_release_service(int service)
{
	int task_idx;
	struct nc_query_in query_in = {0, };
	struct nc_query_out query_out = {0, };

	nc_log(service, "releasing service\n");

	// Get task
	task_idx = get_task(service);
	if (task_idx < 0)
		return 1;

	// Release remote
	query_in.type = NC_QUERY_TYPE_RELEASE;
	query_in.service_id = service;

	// Go 
	if (nc_query(task_idx, &query_in, &query_out))
		nc_log(service,"remote demux release failed\n");

	nc_log(service, "disconnecting from server, closing socket\n");

	close(nc_task[task_idx].socket_fd);

	// Remove locally
	memset(&nc_task[task_idx], 0, sizeof(nc_task[task_idx]));

	return 1;
}

void nc_log(int srvid, const char* format, ...)
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
    strftime(t, sizeof(t), "%F %T", &tm);// %d %H:%M:%S", &tm);

    fprintf(file, "[%s] 0x%04X: ", t, srvid);
    vfprintf(file, format, argptr);
    va_end(argptr);

    fclose(file);
  }
}

//////////////////////////////////////////////////////////////////

static int get_task(int service)
{
	int task_idx;
	struct timeval tv_timeout;
	tv_timeout.tv_sec = NC_TIMEOUT_S;
	tv_timeout.tv_usec = 0;


	// Find service in tasks
	for (task_idx=0; task_idx<NC_MAX_TASKS; task_idx++)
	{
		if (nc_task[task_idx].service == service)
		{
			// Check if IP/Port is still valid
			if (NC_IP && strlen(NC_IP) & NC_PORT)
			{
				// It changed, discard this connection
				if (nc_task[task_idx].server_port != NC_PORT || strcmp(nc_task[task_idx].server_ip, NC_IP))
				{
					close(nc_task[task_idx].socket_fd); nc_task[task_idx].socket_fd=0;
					nc_task[task_idx].service = 0;
					break;
				}
			}

			return task_idx;
		}
	}

	// Find first free index
	for (task_idx=0; task_idx<NC_MAX_TASKS; task_idx++)
	{
		if (!nc_task[task_idx].service)
		{
			// Socket
			nc_task[task_idx].socket_fd=socket(AF_INET,SOCK_STREAM,0);

			// Set Keep alive
			int optval = 1;
			socklen_t optlen = sizeof(optval);
			if(setsockopt(nc_task[task_idx].socket_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0)
				nc_log(service, "could not set KEEPALIVE option (%s)\n", strerror(errno));

			// Set non blocking
			int opts = fcntl(nc_task[task_idx].socket_fd,F_GETFL);
			if (opts < 0)
				nc_log(service, "could not set NONBLOCK option (%s)\n", strerror(errno));
			else
			{
				opts = (opts | O_NONBLOCK);
				if (fcntl(nc_task[task_idx].socket_fd,F_SETFL,opts) < 0)
					nc_log(service, "could not set NONBLOCK option (%s)\n", strerror(errno));
			}

			if (!NC_IP || !strlen(NC_IP) || !NC_PORT)
			{
				nc_log(service, "server not set\n");
				return -1;
			}

			// Set the Server address
			struct sockaddr_in servaddr;
			bzero(&servaddr,sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_addr.s_addr=inet_addr(NC_IP);
			servaddr.sin_port=htons(NC_PORT);

			int connect_ret = connect(nc_task[task_idx].socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
			if (connect_ret < 0)
			{
				if (errno == EINPROGRESS)
				{
					fd_set connect_fd;
					FD_ZERO(&connect_fd);
					FD_SET(nc_task[task_idx].socket_fd, &connect_fd);

					int select_ret = select(nc_task[task_idx].socket_fd+1, NULL, &connect_fd, NULL, &tv_timeout);
					if (select_ret < 0)
					{
						nc_log(service, "connect select error (%s), closing socket\n", strerror(errno));
						close(nc_task[task_idx].socket_fd); nc_task[task_idx].socket_fd=0;
						return -1;
					}
					else if (select_ret == 0)
					{
						nc_log(service, "connect select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
						close(nc_task[task_idx].socket_fd); nc_task[task_idx].socket_fd=0;
						return -1;
					}
				}
				else
				{
					nc_log(service, "connect error (%s), closing socket\n", strerror(errno));
					close(nc_task[task_idx].socket_fd); nc_task[task_idx].socket_fd=0;
					return -1;
				}
			}
			nc_log(service, "task %d, connected to server!\n", task_idx);

			nc_task[task_idx].nb_pids = 0;
			nc_task[task_idx].server_port = NC_PORT;
			strcpy(nc_task[task_idx].server_ip, NC_IP);
			nc_task[task_idx].service = service;

			return task_idx;
		}
	}

	return -1;
}

/* Frame :
 *
 * IN/OUT: HHHH|SSSS|XXXXXXXX|Data
 * HHHH: 4 bytes command
 * SSSS: 4 bytes service ID IN, status OUT
 * XXXXXXXX: 8 bytes data size
 * Data
 *
 * Header size : 16 bytes
 * */


#define NC_HEADER_SIZE 16

static uint32_t nc_query(int task_idx, struct nc_query_in* in, struct nc_query_out* out)
{
	const char* cmd;
	int read_size, sent_size, ret;
	struct timeval tv_timeout;
	tv_timeout.tv_sec = NC_TIMEOUT_S;
	tv_timeout.tv_usec = 0;
        char header[NC_HEADER_SIZE+1];
	char status_buf[5];
	char datasize_buf[9];

	ret = 0;

	// Now We can now talk to server
	switch (in->type)
	{
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

	sprintf(header, "%s%04X%08X", cmd, in->service_id, in->data_size);

	// Send data
	fd_set write_fd;
	FD_ZERO(&write_fd);
	FD_SET(nc_task[task_idx].socket_fd, &write_fd);

	int t = select(nc_task[task_idx].socket_fd+1, NULL, &write_fd, NULL, &tv_timeout);
	if (t <= 0)
	{
		nc_log(nc_task[task_idx].service, "write select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
		goto NC_QUERY_ERROR;
	}

	if (!NC_IP || !strlen(NC_IP) || !NC_PORT)
	{
		nc_log(nc_task[task_idx].service, "server not set\n");
		goto NC_QUERY_ERROR;
	}

	// Set the Server address
	struct sockaddr_in servaddr;
	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=inet_addr(NC_IP);
	servaddr.sin_port=htons(NC_PORT);

	if (nc_verbose)
		nc_log(nc_task[task_idx].service, "sending header [%s]\n", header);

	// Send header
	sent_size=sendto(nc_task[task_idx].socket_fd, header, NC_HEADER_SIZE, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	if (sent_size != NC_HEADER_SIZE)
	{
		nc_log(nc_task[task_idx].service, "error sending to server (%s), closing socket\n", strerror(errno));
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
			FD_SET(nc_task[task_idx].socket_fd, &write_fd);

			int t = select(nc_task[task_idx].socket_fd+1, NULL, &write_fd, NULL, &tv_timeout);
			if (t <= 0)
			{
				nc_log(nc_task[task_idx].service, "write select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
				goto NC_QUERY_ERROR;
			}

			sent_size=sendto(nc_task[task_idx].socket_fd, in->data+total_sent_size, in->data_size-total_sent_size, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
			if (sent_size <= 0)
			{
				nc_log(nc_task[task_idx].service, "error sending to server (%s), closing socket\n", strerror(errno));
				goto NC_QUERY_ERROR;
			}

			total_sent_size += sent_size;
		}
	}

	// Wait for an answer from server
	fd_set read_fd;
	FD_ZERO(&read_fd);
	FD_SET(nc_task[task_idx].socket_fd, &read_fd);

	t = select(nc_task[task_idx].socket_fd+1, &read_fd, NULL, NULL, &tv_timeout);
	if (t < 0)
	{
		nc_log(nc_task[task_idx].service, "read select error (%s), closing socket\n", strerror(errno));
		goto NC_QUERY_ERROR;
	}
	else if (t == 0)
	{
		nc_log(nc_task[task_idx].service, "read select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
		goto NC_QUERY_ERROR;
	}

	// First get header
	read_size=recvfrom(nc_task[task_idx].socket_fd, header, NC_HEADER_SIZE, 0, NULL, NULL);
	if (read_size <= 0)
	{
		nc_log(nc_task[task_idx].service, "error receiving from server (%s), closing socket\n", strerror(errno));
		goto NC_QUERY_ERROR;
	}

	if (read_size != NC_HEADER_SIZE)
	{
		nc_log(nc_task[task_idx].service, "invalid header size %d\n", read_size);
		goto NC_QUERY_ERROR;
	}

	if (nc_verbose)
		nc_log(nc_task[task_idx].service, "received header [%s]\n", header);

	// Get values
	memcpy(status_buf, header+4, 4);
	status_buf[4] = 0;
	memcpy(datasize_buf, header+8, 8);
	datasize_buf[8] = 0;
	sscanf(datasize_buf, "%X", &out->data_size);

	if (!strcmp("GOOD", status_buf))
		out->status = NC_QUERY_STATUS_OK;
	else
	{
		out->status = NC_QUERY_STATUS_ERROR;
		ret = 1;
		goto NC_QUERY_END;
	}

	// Get data
	if (out->data_size)
	{
		int read_data = 0;

		while (read_data < out->data_size)
		{
			t = select(nc_task[task_idx].socket_fd+1, &read_fd, NULL, NULL, &tv_timeout);
			if (t < 0)
			{
				nc_log(nc_task[task_idx].service, "read select error (%s), closing socket\n", strerror(errno));
				goto NC_QUERY_ERROR;
			}
			else if (t == 0)
			{
				nc_log(nc_task[task_idx].service, "read select timeout (%ds), closing socket\n", NC_TIMEOUT_S);
				goto NC_QUERY_ERROR;
			}

			int data_read_size = recvfrom(nc_task[task_idx].socket_fd, out->data+read_data, out->data_size-read_data, 0, NULL, NULL);
			if (data_read_size == 0)
			{
				nc_log(nc_task[task_idx].service, "server disconnected\n");
				goto NC_QUERY_ERROR;
			}
			else if (data_read_size == -1)
			{
				nc_log(nc_task[task_idx].service, "server error\n");
				goto NC_QUERY_ERROR;
			}
			read_data+=data_read_size;
		}
	}

NC_QUERY_END:

	return ret;

NC_QUERY_ERROR:

	close(nc_task[task_idx].socket_fd); nc_task[task_idx].socket_fd=0; nc_task[task_idx].service = 0;

	return 1;

}


