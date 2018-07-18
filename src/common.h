// SPDX-License-Identifier: GPL-2.0
// Copyright © 2017-2018 ANSSI. All Rights Reserved.
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>

int debug(const char *format, ...)
__attribute__ ((format (printf, 1, 2)))
;
