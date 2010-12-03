/* mystruct_conf.c -  */

#include "cgi.h"
#include "pm_conf.h"
#include "../../my_libc/pm_common.h"

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


tPM sPm;

HTTP_META pm_meta_conf[] = {
	{ "PM_FREQUENCE" , 	pm_meta	} ,
	{ "PM_TEMPERATURE", pm_meta	} ,
	{ "PM_L1_VOLTAGE", 	pm_meta	} ,
	{ "PM_L2_VOLTAGE", 	pm_meta	} ,
	{ "PM_L3_VOLTAGE", 	pm_meta	} ,

	{ "PM_L1_CURRENT", 	pm_meta	} ,
	{ "PM_L2_CURRENT", 	pm_meta	} ,
	{ "PM_L3_CURRENT", 	pm_meta	} ,

	{ "PM_L1_POWER", 	pm_meta	} ,
	{ "PM_L2_POWER", 	pm_meta	} ,
	{ "PM_L3_POWER", 	pm_meta	} ,

	{ "PM_L1_ENERGY", 	pm_meta	} ,
	{ "PM_L2_ENERGY", 	pm_meta	} ,
	{ "PM_L3_ENERGY", 	pm_meta	} ,

	{ "PM_L1_PF", 		pm_meta	} ,
	{ "PM_L2_PF", 		pm_meta	} ,
	{ "PM_L3_PF", 		pm_meta	} ,
	{ NULL, 			NULL		}
};

char *pm_pid_files[2]  = { "/var/run/s2e-ttyS0.pid", "/var/run/s2e-ttyS1.pid" };
char *pm_info_files[2] = { "/tmp/s2e-ttyS0.info",    "/tmp/s2e-ttyS1.info"    };

int pm_start (void){

	pm_stop ();

	//nastaveni pocatecnich hodnot
	pm_default_config (&sPm);

	//precteni hodnot ze souboru a jejich nastaveni
	pm_read_config (&sPm);

	return 0;
}

int pm_stop (void){

	//terminate_process (pm_pid_files[0], 1000, S2E_CMD_NAME);

	return 0;
}

int pm_init (HTTP_INFO *info){

	//nastaveni pocatecnich hodnot
	pm_default_config (&sPm);

	//precteni hodnot ze souboru a jejich nastaveni
	pm_read_config (&sPm);

	return 0;
}

int pm_exit (HTTP_INFO *info){

	return 0;
}

int pm_clear (HTTP_INFO *info){

	pm_default_config (&sPm);
	pm_write_config (&sPm);

	return 0;
}


//podle jmena promenne naplni buffer jeji hodnotou
//vola se z www stranek
int pm_meta (HTTP_INFO *info, char *name, char *buffer, int buflen){


	buffer[0] = '\0';

	//VOLTAGE
	if (strcmp (name, "PM_FREQUENCE") == 0) {
		sprintf (buffer, "%d.%d", sPm.frequence/1000, sPm.frequence%1000);
	}
	else if (strcmp (name, "PM_TEMPERATURE") == 0) {
		sprintf (buffer, "%d.%d", sPm.temperature/10, sPm.temperature%10);
	}
	else if (strcmp (name, "PM_L1_VOLTAGE") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[0].voltage/10, sPm.sLines[0].voltage%10);
	}
	else if (strcmp (name, "PM_L2_VOLTAGE") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[1].voltage/10, sPm.sLines[1].voltage%10);
	}
	else if (strcmp (name, "PM_L3_VOLTAGE") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[2].voltage/10, sPm.sLines[2].voltage%10);
	}

	//CURRENT
	else if (strcmp (name, "PM_L1_CURRENT") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[0].current/10,  sPm.sLines[0].current%10);
	}
	else if (strcmp (name, "PM_L2_CURRENT") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[1].current/10, sPm.sLines[1].current%10);
	}
	else if (strcmp (name, "PM_L3_CURRENT") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[2].current/10, sPm.sLines[2].current%10);
	}

	//POWER
	else if (strcmp (name, "PM_L1_POWER") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[0].power/10, sPm.sLines[0].power%10);
	}
	else if (strcmp (name, "PM_L2_POWER") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[1].power/10, sPm.sLines[1].power%10);
	}
	else if (strcmp (name, "PM_L3_POWER") == 0) {
		sprintf (buffer, "%d.%d", sPm.sLines[2].power/10, sPm.sLines[2].power%10);
	}

	//ENERGY
	else if (strcmp (name, "PM_L1_ENERGY") == 0) {
		sprintf (buffer, "%d", sPm.sLines[0].energy);
	}
	else if (strcmp (name, "PM_L2_ENERGY") == 0) {
		sprintf (buffer, "%d", sPm.sLines[1].energy);
	}
	else if (strcmp (name, "PM_L3_ENERGY") == 0) {
		sprintf (buffer, "%d", sPm.sLines[2].energy);
	}

	//POWER FACTOR
	else if (strcmp (name, "PM_L1_PF") == 0) {
		sprintf (buffer, "%d", sPm.sLines[0].pf);
	}
	else if (strcmp (name, "PM_L2_PF") == 0) {
		sprintf (buffer, "%d", sPm.sLines[1].pf);
	}
	else if (strcmp (name, "PM_L3_PF") == 0) {
		sprintf (buffer, "%d", sPm.sLines[2].pf);
	}

	return strlen (buffer);
}

int pm_cgi (HTTP_INFO *info){

	int i;
	tPM *conf;
	tPM temp;
	int ret = 0;

	conf = &sPm;

	memcpy (&temp, conf, sizeof (temp));

	for (i = 0; i < info->argc; i ++) {
		char *ptr = info->argv[i];

		//VOLTAGE
		if (strncmp (ptr, "PM_L1_VOLTAGE=", 14) == 0)
			temp.sLines[0].voltage = atol (ptr + 14);
		else if (strncmp (ptr, "PM_L2_VOLTAGE=", 14) == 0)
			temp.sLines[1].voltage = atol (ptr + 14);
		else if (strncmp (ptr, "PM_L3_VOLTAGE=", 14) == 0)
			temp.sLines[2].voltage = atol (ptr + 14);

		//CURRENT
		else if (strncmp (ptr, "PM_L1_CURRENT=", 14) == 0)
			temp.sLines[0].current = atol (ptr + 14);
		else if (strncmp (ptr, "PM_L2_CURRENT=", 14) == 0)
			temp.sLines[1].current = atol (ptr + 14);
		else if (strncmp (ptr, "PM_L3_CURRENT=", 14) == 0)
			temp.sLines[2].current = atol (ptr + 14);

		//POWER
		else if (strncmp (ptr, "PM_L1_POWER=", 12) == 0)
			temp.sLines[0].power = atol (ptr + 12);
		else if (strncmp (ptr, "PM_L2_POWER=", 12) == 0)
			temp.sLines[1].power = atol (ptr + 12);
		else if (strncmp (ptr, "PM_L3_POWER=", 12) == 0)
			temp.sLines[2].power = atol (ptr + 12);

		//ENERGY
		else if (strncmp (ptr, "PM_L1_ENERGY=", 13) == 0)
			temp.sLines[0].energy = atol (ptr + 13);
		else if (strncmp (ptr, "PM_L1_ENERGY=", 13) == 0)
			temp.sLines[1].energy = atol (ptr + 13);
		else if (strncmp (ptr, "PM_L1_ENERGY=", 13) == 0)
			temp.sLines[2].energy = atol (ptr + 13);
	}

	if (ret == 0) {
		if (memcmp (conf, &temp, sizeof (temp)) != 0) {
			if (pm_write_config (&temp) == 0) {
				memcpy (conf, &temp, sizeof (temp));
                pm_stop();
                pm_start();
            }
		}
	}

	return ret;
}
