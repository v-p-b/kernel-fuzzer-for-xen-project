#ifndef TRACER_H
#define TRACER_H

#include "private.h"

bool setup_sinks(vmi_instance_t vmi);
void clear_sinks(vmi_instance_t vmi);
bool setup_trace(vmi_instance_t vmi);
bool start_trace(vmi_instance_t vmi, addr_t address);
void close_trace(vmi_instance_t vmi);
bool set_cfs(vmi_instance_t vmi);
void setup_target_cf_paddrs(vmi_instance_t vmi);

#endif
