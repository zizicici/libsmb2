/* Change notify keeps the share selected at submission. LGPL-2.1-or-later. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../lib/compat.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

static void reply(struct smb2_context *smb2, enum smb2_command command,
                  int status, void *data)
{
        struct smb2_pdu *pdu = smb2->waitqueue;

        assert(pdu && pdu->header.command == command);
        assert(pdu->header.sync.tree_id == 1);
        assert(smb2_select_tree_id(smb2, 2) == 0);
        smb2->credits++; /* grant one credit with each mock reply */
        smb2->waitqueue = pdu->next;
        pdu->next = NULL;
        smb2->pdu = pdu;
        if (pdu->cb) {
                pdu->cb(smb2, status, data, pdu->cb_data);
        }
        if (!pdu->caller_frees_pdu) {
                smb2_free_pdu(smb2, pdu);
        }
        smb2->pdu = NULL;
}

static void expect_io_error(struct smb2_context *smb2, int status, void *reply, void *data)
{
        int *calls = data;
        assert(status == -EIO && reply == NULL);
        (*calls)++;
}

static void notify_done(struct smb2_context *smb2, int status, void *changes, void *data)
{
        int *calls = data;
        (*calls)++;
        free_smb2_file_notify_change_information(smb2, changes);
}

static void watch_across_tree_switch(struct smb2_context *smb2)
{
        struct smb2_change_notify_reply rep = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        int calls = 0;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(smb2_notify_change_filehandle_async(smb2, fh, 0,
                       SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 1, notify_done, &calls) == 0);
        reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_SUCCESS, &rep);
        reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_CANCELLED, NULL);
        assert(calls == 2);
        assert(!smb2_notify_change_filehandle_async(smb2, fh, 0,
                       SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 1, expect_io_error, &calls));
        reply(smb2, SMB2_CHANGE_NOTIFY, SMB2_STATUS_END_OF_FILE, NULL);
        assert(calls == 3 && !smb2->waitqueue && !smb2->outqueue);
}

static void watch_path(struct smb2_context *smb2)
{
        struct smb2_create_reply created = {0};
        struct smb2_change_notify_reply rep = {0};
        int calls = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        assert(!smb2_notify_change_async(smb2, "dir", 0,
                        SMB2_CHANGE_NOTIFY_FILE_NOTIFY_CHANGE_FILE_NAME, 0, notify_done, &calls));
        reply(smb2, SMB2_CREATE, 0, &created);
        reply(smb2, SMB2_CHANGE_NOTIFY, 0, &rep);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(calls == 1);
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int sockets[2];

        assert(smb2 && !socketpair(AF_UNIX, SOCK_STREAM, 0, sockets));
        smb2->fd = sockets[0];
        smb2->credits = 8;
        assert(!smb2_connect_tree_id(smb2, 1));
        assert(!smb2_connect_tree_id(smb2, 2));
        watch_across_tree_switch(smb2);
        watch_path(smb2);
        smb2_destroy_context(smb2);
        close(sockets[1]);
        return 0;
}
