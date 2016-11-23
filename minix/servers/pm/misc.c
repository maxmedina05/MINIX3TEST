/* Miscellaneous system calls.				Author: Kees J. Bot
 *								31 Mar 2000
 * The entry points into this file are:
 *   do_reboot: kill all processes, then reboot system
 *   do_getsysinfo: request copy of PM data structure  (Jorrit N. Herder)
 *   do_getprocnr: lookup endpoint by process ID
 *   do_getepinfo: get the pid/uid/gid of a process given its endpoint
 *   do_getsetpriority: get/set process priority
 *   do_svrctl: process manager control
 */

#include "pm.h"
#include <minix/callnr.h>
#include <signal.h>
#include <sys/svrctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <minix/com.h>
#include <minix/config.h>
#include <minix/sysinfo.h>
#include <minix/type.h>
#include <minix/ds.h>
#include <machine/archtypes.h>
#include <lib.h>
#include <assert.h>
#include "mproc.h"
#include "kernel/proc.h"

struct utsname uts_val = {
  OS_NAME,		/* system name */
  "noname",		/* node/network name */
  OS_RELEASE,		/* O.S. release (e.g. 3.3.0) */
  OS_VERSION,		/* O.S. version (e.g. Minix 3.3.0 (GENERIC)) */
#if defined(__i386__)
  "i386",		/* machine (cpu) type */
  "i386",		/* architecture */
#elif defined(__arm__)
  "arm",		/* machine (cpu) type */
  "arm",		/* architecture */
#else
#error			/* oops, no 'uname -mk' */
#endif
};

static char *uts_tbl[] = {
  uts_val.arch,
  NULL,			/* No kernel architecture */
  uts_val.machine,
  NULL,			/* No hostname */
  uts_val.nodename,
  uts_val.release,
  uts_val.version,
  uts_val.sysname,
  NULL,			/* No bus */			/* No bus */
};

#if ENABLE_SYSCALL_STATS
unsigned long calls_stats[NR_PM_CALLS];
#endif

/*===========================================================================*
 *				do_sysuname				     *
 *===========================================================================*/
int do_sysuname()
{
/* Set or get uname strings. */
  int r;
  size_t n;
  char *string;
#if 0 /* for updates */
  char tmp[sizeof(uts_val.nodename)];
  static short sizes[] = {
	0,	/* arch, (0 = read-only) */
	0,	/* kernel */
	0,	/* machine */
	0,	/* sizeof(uts_val.hostname), */
	sizeof(uts_val.nodename),
	0,	/* release */
	0,	/* version */
	0,	/* sysname */
  };
#endif

  if (m_in.m_lc_pm_sysuname.field >= _UTS_MAX) return(EINVAL);

  string = uts_tbl[m_in.m_lc_pm_sysuname.field];
  if (string == NULL)
	return EINVAL;	/* Unsupported field */

  switch (m_in.m_lc_pm_sysuname.req) {
  case _UTS_GET:
	/* Copy an uname string to the user. */
	n = strlen(string) + 1;
	if (n > m_in.m_lc_pm_sysuname.len) n = m_in.m_lc_pm_sysuname.len;
	r = sys_datacopy(SELF, (vir_bytes)string, mp->mp_endpoint,
		m_in.m_lc_pm_sysuname.value, (phys_bytes)n);
	if (r < 0) return(r);
	break;

#if 0	/* no updates yet */
  case _UTS_SET:
	/* Set an uname string, needs root power. */
	len = sizes[m_in.m_lc_pm_sysuname.field];
	if (mp->mp_effuid != 0 || len == 0) return(EPERM);
	n = len < m_in.m_lc_pm_sysuname.len ? len : m_in.m_lc_pm_sysuname.len;
	if (n <= 0) return(EINVAL);
	r = sys_datacopy(mp->mp_endpoint, m_in.m_lc_pm_sysuname.value, SELF,
		(phys_bytes)tmp, (phys_bytes)n);
	if (r < 0) return(r);
	tmp[n-1] = 0;
	strcpy(string, tmp);
	break;
#endif

  default:
	return(EINVAL);
  }
  /* Return the number of bytes moved. */
  return(n);
}


/*===========================================================================*
 *				do_getsysinfo			       	     *
 *===========================================================================*/
int do_getsysinfo()
{
  vir_bytes src_addr, dst_addr;
  size_t len;

  /* This call leaks important information. In the future, requests from
   * non-system processes should be denied.
   */
  if (mp->mp_effuid != 0)
  {
	printf("PM: unauthorized call of do_getsysinfo by proc %d '%s'\n",
		mp->mp_endpoint, mp->mp_name);
	sys_diagctl_stacktrace(mp->mp_endpoint);
	return EPERM;
  }

  switch(m_in.m_lsys_getsysinfo.what) {
  case SI_PROC_TAB:			/* copy entire process table */
        src_addr = (vir_bytes) mproc;
        len = sizeof(struct mproc) * NR_PROCS;
        break;
#if ENABLE_SYSCALL_STATS
  case SI_CALL_STATS:
  	src_addr = (vir_bytes) calls_stats;
  	len = sizeof(calls_stats);
  	break; 
#endif
  default:
  	return(EINVAL);
  }

  if (len != m_in.m_lsys_getsysinfo.size)
	return(EINVAL);

  dst_addr = m_in.m_lsys_getsysinfo.where;
  return sys_datacopy(SELF, src_addr, who_e, dst_addr, len);
}

/*===========================================================================*
 *				do_getprocnr			             *
 *===========================================================================*/
int do_getprocnr(void)
{
  register struct mproc *rmp;

  /* This check should be replaced by per-call ACL checks. */
  if (who_e != RS_PROC_NR) {
	printf("PM: unauthorized call of do_getprocnr by %d\n", who_e);
	return EPERM;
  }

  if ((rmp = find_proc(m_in.m_lsys_pm_getprocnr.pid)) == NULL)
	return(ESRCH);

  mp->mp_reply.m_pm_lsys_getprocnr.endpt = rmp->mp_endpoint;
  return(OK);
}

/*===========================================================================*
 *				do_getepinfo			             *
 *===========================================================================*/
int do_getepinfo(void)
{
  struct mproc *rmp;
  endpoint_t ep;
  int slot;

  ep = m_in.m_lsys_pm_getepinfo.endpt;
  if (pm_isokendpt(ep, &slot) != OK)
	return(ESRCH);

  rmp = &mproc[slot];
  mp->mp_reply.m_pm_lsys_getepinfo.uid = rmp->mp_effuid;
  mp->mp_reply.m_pm_lsys_getepinfo.gid = rmp->mp_effgid;
  return(rmp->mp_pid);
}

/*===========================================================================*
 *				do_reboot				     *
 *===========================================================================*/
int do_reboot()
{
  message m;

  /* Check permission to abort the system. */
  if (mp->mp_effuid != SUPER_USER) return(EPERM);

  /* See how the system should be aborted. */
  abort_flag = m_in.m_lc_pm_reboot.how;

  /* notify readclock (some arm systems power off via RTC alarms) */
  if (abort_flag & RB_POWERDOWN) {
	endpoint_t readclock_ep;
	if (ds_retrieve_label_endpt("readclock.drv", &readclock_ep) == OK) {
		message m; /* no params to set, nothing we can do if it fails */
		_taskcall(readclock_ep, RTCDEV_PWR_OFF, &m);
	}
  }

  /* Order matters here. When VFS is told to reboot, it exits all its
   * processes, and then would be confused if they're exited again by
   * SIGKILL. So first kill, then reboot. 
   */

  check_sig(-1, SIGKILL, FALSE /* ksig*/); /* kill all users except init */
  sys_stop(INIT_PROC_NR);		   /* stop init, but keep it around */

  /* Tell VFS to reboot */
  memset(&m, 0, sizeof(m));
  m.m_type = VFS_PM_REBOOT;

  tell_vfs(&mproc[VFS_PROC_NR], &m);

  return(SUSPEND);			/* don't reply to caller */
}

/*===========================================================================*
 *				do_getsetpriority			     *
 *===========================================================================*/
int do_getsetpriority()
{
	int r, arg_which, arg_who, arg_pri;
	struct mproc *rmp;

	arg_which = m_in.m_lc_pm_priority.which;
	arg_who = m_in.m_lc_pm_priority.who;
	arg_pri = m_in.m_lc_pm_priority.prio;	/* for SETPRIORITY */

	/* Code common to GETPRIORITY and SETPRIORITY. */

	/* Only support PRIO_PROCESS for now. */
	if (arg_which != PRIO_PROCESS)
		return(EINVAL);

	if (arg_who == 0)
		rmp = mp;
	else
		if ((rmp = find_proc(arg_who)) == NULL)
			return(ESRCH);

	if (mp->mp_effuid != SUPER_USER &&
	   mp->mp_effuid != rmp->mp_effuid && mp->mp_effuid != rmp->mp_realuid)
		return EPERM;

	/* If GET, that's it. */
	if (call_nr == PM_GETPRIORITY) {
		return(rmp->mp_nice - PRIO_MIN);
	}

	/* Only root is allowed to reduce the nice level. */
	if (rmp->mp_nice > arg_pri && mp->mp_effuid != SUPER_USER)
		return(EACCES);
	
	/* We're SET, and it's allowed.
	 *
	 * The value passed in is currently between PRIO_MIN and PRIO_MAX.
	 * We have to scale this between MIN_USER_Q and MAX_USER_Q to match
	 * the kernel's scheduling queues.
	 */

	if ((r = sched_nice(rmp, arg_pri)) != OK) {
		return r;
	}

	rmp->mp_nice = arg_pri;
	return(OK);
}

/*===========================================================================*
 *				do_svrctl				     *
 *===========================================================================*/
int do_svrctl()
{
  int s, req;
  vir_bytes ptr;
#define MAX_LOCAL_PARAMS 2
  static struct {
  	char name[30];
  	char value[30];
  } local_param_overrides[MAX_LOCAL_PARAMS];
  static int local_params = 0;

  req = m_in.m_lsys_svrctl.request;
  ptr = m_in.m_lsys_svrctl.arg;

  /* Is the request indeed for the PM? */
  if (((req >> 8) & 0xFF) != 'M') return(EINVAL);

  /* Control operations local to the PM. */
  switch(req) {
  case PMSETPARAM:
  case PMGETPARAM: {
      struct sysgetenv sysgetenv;
      char search_key[64];
      char *val_start;
      size_t val_len;
      size_t copy_len;

      /* Copy sysgetenv structure to PM. */
      if (sys_datacopy(who_e, ptr, SELF, (vir_bytes) &sysgetenv, 
              sizeof(sysgetenv)) != OK) return(EFAULT);  

      /* Set a param override? */
      if (req == PMSETPARAM) {
  	if (local_params >= MAX_LOCAL_PARAMS) return ENOSPC;
  	if (sysgetenv.keylen <= 0
  	 || sysgetenv.keylen >=
  	 	 sizeof(local_param_overrides[local_params].name)
  	 || sysgetenv.vallen <= 0
  	 || sysgetenv.vallen >=
  	 	 sizeof(local_param_overrides[local_params].value))
  		return EINVAL;
  		
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key,
            SELF, (vir_bytes) local_param_overrides[local_params].name,
               sysgetenv.keylen)) != OK)
               	return s;
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.val,
            SELF, (vir_bytes) local_param_overrides[local_params].value,
              sysgetenv.vallen)) != OK)
               	return s;
            local_param_overrides[local_params].name[sysgetenv.keylen] = '\0';
            local_param_overrides[local_params].value[sysgetenv.vallen] = '\0';

  	local_params++;

  	return OK;
      }

      if (sysgetenv.keylen == 0) {	/* copy all parameters */
          val_start = monitor_params;
          val_len = sizeof(monitor_params);
      } 
      else {				/* lookup value for key */
      	  int p;
          /* Try to get a copy of the requested key. */
          if (sysgetenv.keylen > sizeof(search_key)) return(EINVAL);
          if ((s = sys_datacopy(who_e, (vir_bytes) sysgetenv.key,
                  SELF, (vir_bytes) search_key, sysgetenv.keylen)) != OK)
              return(s);

          /* Make sure key is null-terminated and lookup value.
           * First check local overrides.
           */
          search_key[sysgetenv.keylen-1]= '\0';
          for(p = 0; p < local_params; p++) {
          	if (!strcmp(search_key, local_param_overrides[p].name)) {
          		val_start = local_param_overrides[p].value;
          		break;
          	}
          }
          if (p >= local_params && (val_start = find_param(search_key)) == NULL)
               return(ESRCH);
          val_len = strlen(val_start) + 1;
      }

      /* See if it fits in the client's buffer. */
      if (val_len > sysgetenv.vallen)
      	return E2BIG;

      /* Value found, make the actual copy (as far as possible). */
      copy_len = MIN(val_len, sysgetenv.vallen); 
      if ((s=sys_datacopy(SELF, (vir_bytes) val_start, 
              who_e, (vir_bytes) sysgetenv.val, copy_len)) != OK)
          return(s);

      return OK;
  }

  default:
	return(EINVAL);
  }
}

/*===========================================================================*
 *				do_getrusage				     *
 *===========================================================================*/
int do_getrusage()
{
	int res = 0;
	clock_t user_time = 0;
	clock_t sys_time = 0;
	struct rusage r_usage;
	u64_t usec;
	if (m_in.m_lc_pm_rusage.who != RUSAGE_SELF &&
		m_in.m_lc_pm_rusage.who != RUSAGE_CHILDREN)
		return EINVAL;
	if ((res = sys_getrusage(&r_usage, who_e)) < 0)
		return res;

	if (m_in.m_lc_pm_rusage.who == RUSAGE_CHILDREN) {
		usec = mp->mp_child_utime * 1000000 / sys_hz();
		r_usage.ru_utime.tv_sec = usec / 1000000;
		r_usage.ru_utime.tv_usec = usec % 1000000;
		usec = mp->mp_child_stime * 1000000 / sys_hz();
		r_usage.ru_stime.tv_sec = usec / 1000000;
		r_usage.ru_stime.tv_usec = usec % 1000000;
	}

	return sys_datacopy(SELF, (vir_bytes)&r_usage, who_e,
		m_in.m_lc_pm_rusage.addr, (vir_bytes) sizeof(r_usage));
}

/* 	do_printdate 	*/

#define LEPOCH_YEAR 1970
#define LLEAPYEAR(lyear) (!((lyear) % 4) && (((lyear) % 100) || !((lyear) % 400)))
#define LYEARSIZE(lyear) (LLEAPYEAR(lyear) ? 366 : 365)

const int lmonnumtable[2][12] = { {31, 28, 31, 30, 31, 30, 31, 31, 30, 
31, 30, 31}, {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31} };

const char lweektable[7][10] = { "THURSDAY", "FRIDAY", "SATURDAY", 
"SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY" };

const char lmonthtable[12][10] = { "JANUARY", "FEBRUARY", "MARCH", 
"APRIL", "MAY", "JUNE", "JULY", "AUGUST", "SEPTEMBER", "OCTOBER", 
"NOVEMBER", "DECEMBER" };

int do_printdate()
{
	time_t curTime, boottime;
	int r, monthnum;
	clock_t uptime, realtime;
	uint32_t system_hz;
	long leftsecs, leftmins, lefthours, leftdays, leftyears, 
weeknum;

	printf("Hello From do_printdate\n");

	if((r = getuptime(&uptime, &realtime, &boottime)) != OK)
		panic("in do_printdate getuptime failed: %d\n", r);

	system_hz = sys_hz();
	curTime = boottime + realtime / system_hz;
	printf("%ld seconds after 1970\n", (long)curTime);

	leftsecs = curTime % 60;
	leftmins = curTime / 60;
	lefthours = leftmins / 60;
	leftmins = leftmins % 60;
	leftdays = lefthours / 24;
	lefthours = lefthours % 24;

	weeknum = leftdays % 7;	

	leftyears = LEPOCH_YEAR;
	
	while (leftdays >= LYEARSIZE(leftyears)) 
	{
		leftdays -= LYEARSIZE(leftyears);
		leftyears++;
	}

	monthnum = 0;

	while (leftdays >= lmonnumtable[LLEAPYEAR(leftyears)][monthnum])
	{
		leftdays -= 
lmonnumtable[LLEAPYEAR(leftyears)][monthnum];
		monthnum++;
	}
	leftdays++;

	printf("%s %s %ld, %ld  %ld : %ld : %ld UTC \n", 
lweektable[weeknum], lmonthtable[monthnum], leftdays, leftyears, 
lefthours, leftmins, leftsecs);

	return OK;
}

/* 	do_printproc 	*/

int do_printproc()
{
	pid_t searchPID = (pid_t)m_in.m_u32.data[0];
	register struct mproc *rmp;	

	printf("Hello From do_printproc \n");
	printf("Information For Proc ID#%d (IF ACTIVE) \n", searchPID);		

	for (rmp = &mproc[0]; rmp < &mproc[NR_PROCS]; rmp++)
		if((rmp->mp_flags & IN_USE) && rmp->mp_pid == searchPID)
		{
			printf(" -- Kernel Endpoint ID: %d \n",
rmp->mp_endpoint);
			printf(" -- Exit Status Storage: %c \n", 
rmp->mp_exitstatus);
			printf(" -- Signal # for Killed Procs: %c \n", 
rmp->mp_sigstatus);
			printf(" -- Process Group ID: %d \n", 
rmp->mp_procgrp);
			printf(" -- PID This Process is Waiting For: %d \n", rmp->mp_wpid);
			printf(" -- Parent Process Index: %d \n", 
rmp->mp_parent);
			printf(" -- Tracer Process Index: %d \n", 
rmp->mp_tracer);
			return (OK);
		}
	
	printf("ACTIVE PROCESS ID#%d NOT FOUND \n", searchPID);

	return -1;
}

int do_semdown()
{
	int sem_id = (int) m_in.m_u32.data[0];
	register struct mproc *rmp = mp;

	if(sem_id >= 31 || sem_id < 0)
	{
		printf("\nERROR: SEM_ID OUT OF RANGE\n");
		return -1;
	}

	if(rmp->mp_endpoint == 0)
	{
		printf("\nLAZY ERROR: ENDPOINT IS 0\n");
		return -1;
	}

	if(msemaphores[sem_id].created == 0)
	{
		printf("\nERROR: SEM NOT CREATED\n");
		return -1;
	}

	if(msemaphores[sem_id].value == 0)
	{
		if(msemaphores[sem_id].owner_e == NULL && msemaphores[sem_id].phead == NULL && msemaphores[sem_id].mtail == NULL)
		{
			msemaphores[sem_id].value--;
			msemaphores[sem_id].owner_e = rmp;
		}
		else
		{
			printf("\nERROR:OWNER HEAD OR TAIL NOT NULL\n");
			return -1;
		}
	}
	else if(msemaphores[sem_id].value == -1)
	{
		if(msemaphores[sem_id].owner_e != NULL && msemaphores[sem_id].owner_e != rmp)
		{
			if(rmp->sem_next != NULL)
			{
				printf("\nWARNING: SEM_NEXT IS NOT NULL\n");
			}

			if(msemaphores[sem_id].phead == NULL && msemaphores[sem_id].mtail == NULL)
			{
				msemaphores[sem_id].phead = rmp;
				msemaphores[sem_id].mtail = rmp;
			}
			else if(msemaphores[sem_id].phead != NULL && msemaphores[sem_id].mtail != NULL)
			{
				msemaphores[sem_id].mtail->sem_next = rmp;
				msemaphores[sem_id].mtail = rmp;
			}
			else 
			{
				printf("\nERROR: HEAD AND TAIL NOT SYNCHRNIZED\n");
				return -1;
			}

			if(sys_kill(rmp->mp_endpoint, SIGSTOP) != OK) 
			{
				printf("\nERROR:BLOCK PROCESS FAILED\n");
				return -1;
			}

		}
		else
		{
			printf("\nERROR: OWNER SHOULD BE EMPTY OR IS SAME AS CALLER\n");
			printf("\nVALUE: %d, OWNER %p, HEAD: %p, TAIL: %p\n", msemaphores[sem_id].value, msemaphores[sem_id].owner_e, msemaphores[sem_id].phead, msemaphores[sem_id].mtail);
			return -1;
		}
	}
	else
	{
		printf("\nERROR: SEM VALUE IS NOT 1 or 0\n");
		return -1;
	}

	return 0;
}

int do_semup()
{
	int sem_id = (int) m_in.m_u32.data[0];
	register struct mproc *rmp = mp;
	register struct mproc *temp;

	if(sem_id >= 31 || sem_id < 0)
	{
		printf("\nERROR: SEM ID OUT OF RANGE\n");
		return -1;
	}

	if(rmp->mp_endpoint == 0)
	{
		printf("\nLAZY ERROR: ENDPOINT IS 0\n");
		return -1;
	}
	
	if(msemaphores[sem_id].created == 0)
	{
		printf("\nERROR: SEM NOT CREATED \n");
		return -1;
	}

	if(msemaphores[sem_id].owner_e == NULL || msemaphores[sem_id].owner_e != rmp)
	{
		printf("\nERROR:OWNER IS EITHER NULL OR DIFFERENT\n");
		return -1;
	}

	if(msemaphores[sem_id].value == -1)
	{
		if(msemaphores[sem_id].phead == NULL && msemaphores[sem_id].mtail == NULL)
		{
			msemaphores[sem_id].value++;
			msemaphores[sem_id].owner_e = NULL;
		}
		else if(msemaphores[sem_id].phead != NULL && msemaphores[sem_id].mtail != NULL)
		{
			temp = msemaphores[sem_id].phead;
			msemaphores[sem_id].phead = temp->sem_next;
			msemaphores[sem_id].owner_e = temp;
			if(msemaphores[sem_id].phead == NULL)
			{
				msemaphores[sem_id].mtail = NULL;
			}
			temp->sem_next = NULL;
			if(sys_kill(temp->mp_endpoint, SIGCONT) != OK)
			{
				printf("\nERROR: UNBLOCK FAILED\n");
				return -1;
			}
		}
		else
		{
			printf("\nERROR:SEM_UP INCONSISTENT HEAD AND TAIL\n");
			return -1;
		}
	}
	else
	{
		printf("\nERROR: SEM VALUE SHOULD BE SET 0\n");
		return -1;
	}

	return 0;
}


int do_semcreate()
{
	int sem_id = m_in.m_u32.data[0];
	register struct mproc *rmp = mp;

	if(msemaphores[sem_id].created == 0 && msemaphores[sem_id].owner_e == rmp)
	{
		msemaphores[sem_id].created = 1;
	}
	else
	{
		return -1;
	}	

	return 0;	
}

int do_semdel()
{
	int sem_id = m_in.m_u32.data[0];
	register struct mproc *rmp = mp;

	if(msemaphores[sem_id].owner_e == rmp && msemaphores[sem_id].created == 1)
	{
		if(msemaphores[sem_id].phead == NULL && msemaphores[sem_id].mtail == NULL)
		{
			msemaphores[sem_id].created = 0;
			msemaphores[sem_id].value = 0;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}

