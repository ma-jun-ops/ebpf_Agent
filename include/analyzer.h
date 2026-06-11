#ifndef ANALYZER_H
#define ANALYZER_H

#include "common.h"

void analyzer_set_verbose(int v);
void analyzer_process(const struct process_event *e);

#endif
