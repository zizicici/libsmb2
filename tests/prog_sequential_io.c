/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "smb2.h"
#include "libsmb2.h"

static int check_io(struct smb2_context *smb2, const char *path)
{
        struct smb2fh *fh = smb2_open(smb2, path, O_RDWR | O_CREAT | O_TRUNC);

        if (!fh || smb2_lseek(smb2, fh, 1, SEEK_SET, NULL) != 1 ||
            smb2_lseek(smb2, fh, -9, SEEK_END, NULL) != -EINVAL ||
            smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) != 1 ||
            smb2_lseek(smb2, fh, INT64_MAX, SEEK_CUR, NULL) != -EINVAL ||
            smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) != 1) {
                return -1;
        }
        return smb2_close(smb2, fh);
}

int main(int argc, char **argv)
{
        struct smb2_context *smb2;
        struct smb2_url *url;
        int rc = -1;

        if (argc != 2 || (smb2 = smb2_init_context()) == NULL) {
                return 1;
        }
        url = smb2_parse_url(smb2, argv[1]);
        smb2_set_timeout(smb2, 10);
        if (url && !smb2_connect_share(smb2, url->server, url->share, url->user)) {
                rc = check_io(smb2, url->path);
                smb2_unlink(smb2, url->path);
                smb2_disconnect_share(smb2);
        }
        if (rc) {
                fprintf(stderr, "Sequential file I/O check failed: %s\n", smb2_get_error(smb2));
        }
        smb2_destroy_url(url);
        smb2_destroy_context(smb2);
        return rc != 0;
}
