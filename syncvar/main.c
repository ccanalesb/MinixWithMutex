/* Data Store Server. 
 * This service implements a little publish/subscribe data store that is 
 * crucial for the system's fault tolerance. Components that require state
 * can store it here, for later retrieval, e.g., after a crash and subsequent
 * restart by the reincarnation server. 
 * 
 * Created:
 *   Oct 19, 2005	by Jorrit N. Herder
 */

#include "inc.h"	/* include master header file */
#include <minix/endpoint.h>

/* Allocate space for the global variables. */
static endpoint_t who_e;	/* caller's proc number */
static int callnr;		/* system call number */



/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
int main(int argc, char **argv)
{
/* This is the main routine of this service. The main loop consists of 
 * three major activities: getting new work, processing the work, and
 * sending the reply. The loop never terminates, unless a panic occurs.
 */
  message m;
  int result;                 

  /* SEF local startup. */
  env_setargs(argc, argv);

  /* Main loop - get work and do it, forever. */         
  while (TRUE) {              
      printf("hola");
      if (is_notify(callnr)) {
          printf("DS: warning, got illegal notify from: %d\n", m.m_source);
          result = EINVAL;
      }


      /* Finally send reply message, unless disabled. */
      if (result != EDONTREPLY) {
          m.m_type = result;  		/* build reply message */
      }
  }
  return(OK);				/* shouldn't come here */
}
