/* Offline checks for handle-based symlink deletion and cleanup. LGPL-2.1-or-later. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
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

enum operation { UNLINK_DIRECTORY, UNLINK_NO_TAG, UNLINK_TAG_EOF, UNLINK_LINK, CREATE_LINK, FAIL_CREATE_LINK };

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
        if (command == SMB2_IOCTL && status == SMB2_STATUS_SUCCESS) {
                struct smb2_iovec *rp = &pdu->out.iov[2];
                uint16_t offset, length;
                const char *name;

                assert(rp->len >= 20);
                offset = rp->buf[8] | (rp->buf[9] << 8);
                length = rp->buf[10] | (rp->buf[11] << 8);
                assert(20u + offset + length <= rp->len);
                name = smb2_utf16_to_utf8((const uint16_t *)(rp->buf + 20 + offset), length / 2);
                assert(name && !strcmp(name, "\\??\\UNC\\server\\share\\target"));
                free((void *)name);
        }
        if (command == SMB2_SET_INFO) {
                assert(pdu->out.iov[1].buf[3] == SMB2_FILE_DISPOSITION_INFORMATION);
                assert(pdu->out.iov[2].buf[0] == 1);
        }
        if (smb2->passthrough) {
                assert(!pdu->report_pending);
                assert(result->completed == 0 && smb2->waitqueue == pdu);
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
        struct smb2_query_info_reply query = {0};
        struct smb2_file_attribute_tag_info *tag;
        int unlink_op = op <= UNLINK_LINK;

        smb2->credits = 32;
        assert(!smb2_select_tree_id(smb2, original_tree));
        if (unlink_op) {
                assert(!smb2_unlink_async(smb2, "link", completed, &result));
        } else {
                assert(!smb2_symlink_async(smb2, op == CREATE_LINK ? "//server/share/target" : "target",
                                           "link", SMB2_SYMLINK_DIRECTORY,
                                           completed, &result));
        }
        /* New operations on this context now use a different share. */
        assert(!smb2_select_tree_id(smb2, other_tree));
        if (unlink_op) {
                reply(smb2, SMB2_CREATE, SMB2_STATUS_FILE_IS_A_DIRECTORY, NULL, &result, -1);
                reply(smb2, SMB2_CLOSE, SMB2_STATUS_FILE_IS_A_DIRECTORY, NULL, &result, -1);
        }
        memcpy(created.file_id, opened_id, sizeof(opened_id));
        reply(smb2, SMB2_CREATE, 0, &created, &result, -1);
        if (op == UNLINK_NO_TAG) {
                reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_NOT_SUPPORTED, NULL, &result, -1);
        } else if (op == UNLINK_TAG_EOF) {
                reply(smb2, SMB2_QUERY_INFO, SMB2_STATUS_END_OF_FILE, NULL, &result, -1);
        } else if (unlink_op) {
                tag = smb2_alloc_init(smb2, sizeof(*tag));
                assert(tag);
                tag->file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
                if (op == UNLINK_LINK) {
                        tag->file_attributes |= SMB2_FILE_ATTRIBUTE_REPARSE_POINT;
                        tag->reparse_tag = SMB2_REPARSE_TAG_SYMLINK;
                }
                query.output_buffer = tag;
                reply(smb2, SMB2_QUERY_INFO, 0, &query, &result, -1);
        } else {
                reply(smb2, SMB2_IOCTL, op == FAIL_CREATE_LINK ? SMB2_STATUS_ACCESS_DENIED : 0,
                      NULL, &result, -1);
        }
        if (op == UNLINK_LINK || op == FAIL_CREATE_LINK) {
                reply(smb2, SMB2_SET_INFO, 0, NULL, &result, 16);
        }
        reply(smb2, SMB2_CLOSE, 0, NULL, &result, 8);
        assert(result.completed == 1 && smb2->waitqueue == NULL);
        assert((result.status == 0) == (op == UNLINK_LINK || op == CREATE_LINK));
        if (op == UNLINK_DIRECTORY || op == UNLINK_NO_TAG) {
                assert(result.status == -EISDIR);
        }
        if (op == UNLINK_TAG_EOF) {
                assert(result.status == -EIO);
        }
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
                for (op = UNLINK_DIRECTORY; op <= FAIL_CREATE_LINK; op++) {
                        run(smb2, op);
                }
        }
        smb2_destroy_context(smb2);
        close(sockets[1]);
        return 0;
}
