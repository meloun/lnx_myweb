/* mystruct_conf.c -  */

#include "cgi.h"
#include "io_conf.h"
#include "../../my_libc/io_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>


tIO sIo;

HTTP_META io_meta_conf[] = {
	{ "IO_INPUT_1_STATE", 	io_meta	} ,
	{ "IO_INPUT_2_STATE", 	io_meta	} ,
	{ "IO_OUTPUT_1_CURRENT_STATE@", 	io_meta	} ,
	{ "IO_OUTPUT_2_CURRENT_STATE@", 	io_meta	} ,
	{ "IO_OUTPUT_1_DEFAULT_STATE@", 	io_meta	} ,
	{ "IO_OUTPUT_2_DEFAULT_STATE@", 	io_meta	} ,
	{ "IO_STATIC_VAR", 		io_meta	} ,
	{ NULL, 			NULL		}
};


char *commands[2]   = {
	"/bin/s2e -0 -C /etc/s2e-ttyS0.conf",
	"/bin/s2e -1 -C /etc/s2e-ttyS1.conf"
};


char *pid_files[2]  = { "/var/run/s2e-ttyS0.pid", "/var/run/s2e-ttyS1.pid" };
char *info_files[2] = { "/tmp/s2e-ttyS0.info",    "/tmp/s2e-ttyS1.info"    };

//static int read_info (struct IO_t *conf_data);


int io_start (void){

	io_stop ();

	//nastaveni pocatecnich hodnot
	io_default_config (&sIo);

	//precteni hodnot ze souboru a jejich nastaveni
	io_read_config (&sIo);

	return 0;
}

int io_stop (void){

	//terminate_process (pid_files[0], 1000, IO_CMD_NAME);

	return 0;
}

int io_init (HTTP_INFO *info){

	//nastaveni pocatecnich hodnot
	io_default_config (&sIo);

	//precteni hodnot ze souboru a jejich nastaveni
	io_read_config (&sIo);

	return 0;
}

int io_exit (HTTP_INFO *info){

	return 0;
}

int io_clear (HTTP_INFO *info){

	io_default_config (&sIo);
	io_write_config (&sIo);

	return 0;
}


//podle jmena promenne naplni buffer jeji hodnotou
//vola se z www stranek
int io_meta (HTTP_INFO *info, char *name, char *buffer, int buflen){


	tIO *conf;
	conf = &sIo;

	buffer[0] = '\0';

	if (strcmp (name, "IO_INPUT_1_STATE") == 0) {
		sprintf (buffer, "%d", conf->ext_inputs[0].current_state);
	}
	else if (strcmp (name, "IO_INPUT_2_STATE") == 0) {
		sprintf (buffer, "%d", conf->ext_inputs[1].current_state);
	}
	else if (strncmp (name, "IO_OUTPUT_1_CURRENT_STATE@",27) == 0) {
		if(atoi(name+27) == conf->ext_outputs[0].current_state)
			strcpy(buffer, "selected");
			//sprintf (buffer, "%d", conf->ext_outputs[0]);
	}
	else if (strncmp (name, "IO_OUTPUT_2_CURRENT_STATE@",27) == 0) {
		if(atoi(name+27) == conf->ext_outputs[1].current_state)
			strcpy(buffer, "selected");
		//sprintf (buffer, "%d", conf->ext_outputs[1]);
	}
	else if (strncmp (name, "IO_OUTPUT_1_DEFAULT_STATE@",27) == 0) {
		if(atoi(name+27) == conf->ext_outputs[0].default_state)
			strcpy(buffer, "selected");
			//sprintf (buffer, "%d", conf->ext_outputs[0]);
	}
	else if (strncmp (name, "IO_OUTPUT_2_DEFAULT_STATE@",27) == 0) {
		if(atoi(name+27) == conf->ext_outputs[1].default_state)
			strcpy(buffer, "selected");
		//sprintf (buffer, "%d", conf->ext_outputs[1]);
	}

	return strlen (buffer);
}

int io_cgi (HTTP_INFO *info)
{
	int chan = info->chan ? info->chan - 1 : 0;
	int i;
	tIO *conf;
	tIO temp;
	int ret = 0;

	conf = &sIo;

	memcpy (&temp, conf, sizeof (temp));

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];

		if (strncmp (ptr, "IO_OUTPUT_1_CURRENT_STATE=", 27) == 0)
			temp.ext_outputs[0].current_state = atol (ptr + 27);
		else if (strncmp (ptr, "IO_OUTPUT_2_CURRENT_STATE=", 27) == 0)
			temp.ext_outputs[1].current_state = atol (ptr + 27);
		else if (strncmp (ptr, "IO_OUTPUT_1_DEFAULT_STATE=", 27) == 0)
			temp.ext_outputs[0].default_state = atol (ptr + 27);
		else if (strncmp (ptr, "IO_OUTPUT_2_DEFAULT_STATE=", 27) == 0)
			temp.ext_outputs[1].default_state = atol (ptr + 27);
	}

	if (ret == 0) {
		if (memcmp (conf, &temp, sizeof (temp)) != 0) {
			if (io_write_config (&temp) == 0) {
				memcpy (conf, &temp, sizeof (temp));
                io_stop();
                io_start();
            }
		}
	}

	return ret;
}

/*
static int read_info (struct IO_t *conf_data)
{
	FILE *fp;
	char buffer[128];
	int i;
	int pid = 0;

	unlink (info_files[0]);

	if ((pid = getpid_by_file (pid_files[0])) < 0)
		return -1;

    if (!is_active_proc(pid, IO_CMD_NAME))
    {
        unlink(pid_files[0]);
        return -1;
    }

	kill (pid, SIGUSR1);

	for (i = 0; i < 30; i ++) {
		msleep (100);
		if ((fp = fopen (info_files[0], "r")) != NULL) {

			while (fgets(buffer, sizeof (buffer), fp)!=NULL){
				char *ptr = buffer;
				if (strncmp (ptr , "tty_sent:", 9) == 0) {
					ptr += 9;
					ptr = skip_brank(ptr);
					conf_data->tty_sent = atol (ptr);
				}
				if (strncmp (ptr , "tty_rcvd:", 9) == 0) {
					ptr += 9;
					ptr = skip_brank(ptr);
					conf_data->tty_rcvd = atol (ptr);
				}
				if (strncmp (ptr , "remote_host:", 12) == 0) {
					unsigned long value;
					ptr += 12;
					ptr = skip_brank(ptr);
					value = (unsigned long) inet_addr(ptr);
					memcpy (conf_data->remote_host, &value, 4);
				}
				if (strncmp (ptr , "remote_port:", 12) == 0) {
					ptr += 12;
					ptr = skip_brank(ptr);
					conf_data->remote_port = atol (ptr);
				}
			}
			fclose (fp);
			unlink (info_files[0]);
			break;
		}
	}
	return 0;
}*/
