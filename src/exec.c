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

#include <stdlib.h>
#include <unistd.h>

#include <sys/wait.h>

#include "exec.h"
#include "log.h"

int
enftun_exec(const char* const argv[], const char* const envp[])
{
    int status;
    pid_t pid;

    pid = fork();

    /* child */
    if (pid == 0)
    {
        execve(argv[0], (char* const*) &argv[0], (char* const*) envp);
        exit(127);
    }

    /* parent */
    if (pid < 0)
    {
        enftun_log_error("Failed to run program %s\n", argv[0]);
        return -1;
    }
    else if (waitpid(pid, &status, 0) != pid)
    {
        enftun_log_error("Failed to wait for program %s to complete\n",
                         argv[0]);
        return -1;
    }

    if (!WIFEXITED(status))
    {
        enftun_log_error("Program %s failed\n", argv[0]);
        return -1;
    }

    if (WEXITSTATUS(status) != 0)
    {
        enftun_log_error("Program %s failed\n", argv[0]);
        return -WEXITSTATUS(status);
    }

    return 0;
}
