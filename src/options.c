/*
 * Copyright 2018 Xaptum, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "memory.h"
#include "options.h"

static
void print_usage()
{
    puts("usage: enftun [-h] -c conf_file [-p key]");
}

int
enftun_options_init(struct enftun_options* opts)
{
    CLEAR(*opts);

    opts->action = ENFTUN_ACTION_RUN;

    opts->conf_file = "";

    return 0;
}

int
enftun_options_free(struct enftun_options* opts)
{
    CLEAR(*opts);
    return 0;
}

int
enftun_options_parse_argv(struct enftun_options* opts,
                          const int argc,
                          char *argv[])
{
    int c;
    while ((c = getopt(argc, argv, "hc:p:")) != -1)
    {
        switch (c)
        {
        case 'h':
            print_usage();
            return -EINVAL;
        case 'c':
            opts->conf_file = optarg;
            break;
        case 'p':
            opts->action = ENFTUN_ACTION_PRINT;
            opts->print_arg = optarg;
            break;
        default:
            print_usage();
            return -EINVAL;
        }
    }

    return 0;
}
