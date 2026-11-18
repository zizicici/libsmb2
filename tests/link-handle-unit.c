/* Offline checks for handle-based symlink creation and cleanup. LGPL-2.1-or-later. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
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

static const uint32_t original_tree = 11, other_tree = 22;
static const smb2_file_id opened_id = {1, 2, 3, 4, 5, 6, 7, 8};

enum operation { CREATE_LINK, FAIL_CREATE_LINK };

struct result {
        int completed;
        int status;
};

static void completed(struct smb2_context *smb2 _U_, int status, void *reply _U_, void *arg)
{
        struct result *result = arg;
        result->completed++;
        result->status = status;
}

static void reply(struct smb2_context *smb2, enum smb2_command command, uint32_t status,
                  void *data, struct result *result, int id_offset)
{
        struct smb2_pdu *pdu = smb2->waitqueue;

        assert(pdu && pdu->header.command == command && pdu->header.sync.tree_id == original_tree);
        if (id_offset >= 0) {
                assert(!memcmp(pdu->out.iov[1].buf + id_offset, opened_id, sizeof(opened_id)));
        }
        if (command == SMB2_SET_INFO) {
                assert(pdu->out.iov[1].buf[3] == SMB2_FILE_DISPOSITION_INFORMATION);
                assert(pdu->out.iov[2].buf[0] == 1);
        }
        if (smb2->passthrough) {
                pdu->cb(smb2, SMB2_STATUS_PENDING, NULL, pdu->cb_data);
                assert(result->completed == 0 && smb2->waitqueue == pdu);
        }
        smb2->waitqueue = pdu->next;
        pdu->next = NULL;
        pdu->cb(smb2, status, data, pdu->cb_data);
        smb2_free_pdu(smb2, pdu);
}

static void run(struct smb2_context *smb2, enum operation op)
{
        struct result result = {0};
        struct smb2_create_reply created = {0};

        smb2->credits = 32;
        assert(!smb2_select_tree_id(smb2, original_tree));
        assert(!smb2_symlink_async(smb2, "target", "link", SMB2_SYMLINK_DIRECTORY,
                                   completed, &result));
        /* New operations on this context now use a different share. */
        assert(!smb2_select_tree_id(smb2, other_tree));
        memcpy(created.file_id, opened_id, sizeof(opened_id));
        reply(smb2, SMB2_CREATE, 0, &created, &result, -1);
        reply(smb2, SMB2_IOCTL, op == FAIL_CREATE_LINK ? SMB2_STATUS_ACCESS_DENIED : 0,
              NULL, &result, -1);
        if (op == FAIL_CREATE_LINK) {
                reply(smb2, SMB2_SET_INFO, 0, NULL, &result, 16);
        }
        reply(smb2, SMB2_CLOSE, 0, NULL, &result, 8);
        assert(result.completed == 1 && smb2->waitqueue == NULL);
        assert((result.status == 0) == (op == CREATE_LINK));
        if (op == FAIL_CREATE_LINK) {
                assert(result.status == -EACCES);
        }
}

int main(void)
{
        struct smb2_context *smb2 = smb2_init_context();
        int sockets[2], passthrough;
        enum operation op;

        assert(smb2 && socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        smb2->fd = sockets[0];
        assert(!smb2_connect_tree_id(smb2, original_tree));
        assert(!smb2_connect_tree_id(smb2, other_tree));
        for (passthrough = 0; passthrough <= 1; passthrough++) {
                smb2_set_passthrough(smb2, passthrough);
                for (op = CREATE_LINK; op <= FAIL_CREATE_LINK; op++) {
                        run(smb2, op);
                }
        }
        smb2_destroy_context(smb2);
        close(sockets[1]);
        return 0;
}
