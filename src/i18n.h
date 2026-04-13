#ifndef SECDAT_I18N_H
#define SECDAT_I18N_H

#include <libintl.h>

#define _(message) gettext(message)

void secdat_i18n_init(const char *argv0);

#endif
