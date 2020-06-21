#include <stdint.h>
#include <stdbool.h>

#include "forkvm.h"

// extern uint32_t domid, forkdomid;
extern int vcpus;
extern xc_interface *xc;

bool fork_vm(uint32_t my_domid, uint32_t *my_forkdomid)
{
    int rc;
    struct xen_domctl_createdomain create = {0};
    create.flags |= XEN_DOMCTL_CDF_hvm;
    create.flags |= XEN_DOMCTL_CDF_hap;
    create.flags |= XEN_DOMCTL_CDF_oos_off;
    create.arch.emulation_flags = (XEN_X86_EMU_ALL & ~XEN_X86_EMU_VPCI);
    create.ssidref = 11; // SECINITSID_DOMU
    create.max_vcpus = vcpus;
    create.max_evtchn_port = 1023;
    create.max_grant_frames = LIBXL_MAX_GRANT_FRAMES_DEFAULT;
    create.max_maptrack_frames = LIBXL_MAX_MAPTRACK_FRAMES_DEFAULT;

    if ( (rc = xc_domain_create(xc, my_forkdomid, &create)) )
        return false;

    if ( (rc = xc_memshr_fork(xc, my_domid, *my_forkdomid, true, true)) )
    {
        xc_domain_destroy(xc, *my_forkdomid);
        return false;
    }

    return true;
}
