#ifndef SECDAT_EXEC_INJECT_H
#define SECDAT_EXEC_INJECT_H

#include "cli.h"

int secdat_exec_command(const struct secdat_cli *cli);
int secdat_exec_completion_command_index(int argc, char **argv);

#endif