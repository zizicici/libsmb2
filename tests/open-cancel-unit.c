/* Offline checks for the lifetime of a caller-owned CREATE. LGPL-2.1-or-later. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <fcntl.h>
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

struct callbacks {
        int completed;
        int released;
};

static void completed(struct smb2_context *smb2, int status, void *reply, void *data)
{
        struct callbacks *calls = data;
        calls->completed++;
}

static void released(void *data)
{
        struct callbacks *calls = data;
        calls->released++;
}

static void release_on_completion(struct smb2_context *smb2, int status,
                                  void *reply, void *data)
{
        struct smb2_pdu **owner = data;
        assert(status < 0 && reply == NULL);
        smb2_free_pdu(smb2, *owner);
        *owner = NULL;
}

/* Complete one valid response with the same ownership rules as the receiver.
 * The socketpair lets us also check which SMB command was really sent next. */
static void reply(struct smb2_context *smb2, enum smb2_command command,
                  int status, void *data)
{
        struct smb2_pdu *pdu = smb2->waitqueue;

        assert(pdu && pdu->header.command == command);
        assert(pdu->header.sync.tree_id == 1);
        assert(smb2_select_tree_id(smb2, 2) == 0);
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

/* Cancel an opendir while its CREATE, QUERY_DIRECTORY or CLOSE is pending. */
static void cancel_directory(struct smb2_context *smb2, enum smb2_command stage)
{
        struct callbacks calls = {0};
        struct smb2_pdu *owner;
        struct smb2_create_reply created = {0};

        assert(smb2_select_tree_id(smb2, 1) == 0);
        owner = smb2_opendir_async_pdu(smb2, "", completed, &calls, released);
        assert(owner);
        if (stage == SMB2_CREATE) {
                smb2_free_pdu(smb2, owner);
        }
        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
        if (stage != SMB2_CREATE) {
                if (stage == SMB2_QUERY_DIRECTORY) {
                        smb2_free_pdu(smb2, owner);
                }
                reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_NO_MORE_FILES, NULL);
                if (stage == SMB2_CLOSE) {
                        smb2_free_pdu(smb2, owner);
                }
        }
        assert(calls.released == 1);
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        assert(calls.completed == 0 && calls.released == 1);
        assert(smb2->dirs == NULL);
}

static void cancel_symlink_retry(struct smb2_context *smb2, int sent)
{
        struct callbacks calls = {0};
        struct smb2_pdu *owner;
        struct smb2_create_reply created = {0};
        /* Relative symlink with substitute and print name "x". */
        uint8_t target[] = {
                26,0,0,0, 'S','Y','M','L', 0x0c,0,0,0xa0, 14,0,0,0,
                0,0,2,0, 0,0,2,0, 1,0,0,0, 'x',0
        };
        struct smb2_error_reply link = {0};

        link.byte_count = sizeof(target);
        link.error_data = target;
        assert(smb2_select_tree_id(smb2, 1) == 0);
        owner = smb2_open_async_pdu(smb2, "link", O_RDONLY, completed, &calls, released);
        assert(owner);
        if (!sent) {
                smb2->credits = 0;
        }
        reply(smb2, SMB2_CREATE, SMB2_STATUS_STOPPED_ON_SYMLINK, &link);
        smb2_free_pdu(smb2, owner);
        assert(calls.released == 1 && calls.completed == 0);
        if (sent) {
                reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
                reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        } else {
                assert(smb2->outqueue == NULL && smb2->waitqueue == NULL);
                smb2->credits = 32;
        }
        assert(calls.released == 1 && calls.completed == 0);
        assert(smb2->fhs == NULL);
}

static void disconnect_during_copy(struct smb2_context *smb2, int peer)
{
        struct smb2_srv_copychunk_resume_key key = {0};
        struct smb2_srv_copychunk chunk = {0};
        struct smb2_srv_copychunk_reply result;
        smb2_file_id id = {0};
        struct smb2fh *fh = smb2_fh_from_file_id(smb2, &id);

        assert(fh);
        chunk.length = 1;
        assert(shutdown(peer, SHUT_WR) == 0);
        assert(smb2_request_resume_key(smb2, fh, &key) < 0);
        assert(smb2_copychunk(smb2, SMB2_FSCTL_SRV_COPYCHUNK, &key,
                              fh, &chunk, 1, &result) < 0);
        assert(smb2_server_side_copy(smb2, SMB2_FSCTL_SRV_COPYCHUNK,
                                     fh, fh, &chunk, 1, &result) < 0);
        /* Context teardown below completes the outstanding IOCTL callbacks. */
}

int main(void)
{
        int pair[2];
        struct smb2_context *smb2 = smb2_init_context();
        struct smb2_pdu *owner;

        assert(smb2);
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
                return 1;
        }
        smb2->fd = pair[0];
        smb2->credits = 32;
        assert(smb2_connect_tree_id(smb2, 1) == 0);
        assert(smb2_connect_tree_id(smb2, 2) == 0);
        cancel_directory(smb2, SMB2_CREATE);
        cancel_directory(smb2, SMB2_QUERY_DIRECTORY);
        cancel_directory(smb2, SMB2_CLOSE);
        cancel_symlink_retry(smb2, 0);
        cancel_symlink_retry(smb2, 1);
        assert(smb2_select_tree_id(smb2, 1) == 0);
        owner = smb2_open_async_pdu(smb2, "missing", O_RDONLY,
                                    release_on_completion, &owner, NULL);
        assert(owner);
        reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_NOT_FOUND, NULL);
        assert(owner == NULL && smb2->fhs == NULL);
        disconnect_during_copy(smb2, pair[1]);
        smb2_destroy_context(smb2);
        close(pair[1]);
        return 0;
}
