/* Offline checks for the lifetime of a caller-owned CREATE. LGPL-2.1-or-later. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#undef NDEBUG
#include <assert.h>
#include <errno.h>
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

static void directory_query_failure(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_create_reply created = {0};

        assert(smb2_select_tree_id(smb2, 1) == 0);
        assert(smb2_opendir_async(smb2, "", completed, &calls) == 0);
        reply(smb2, SMB2_CREATE, SMB2_STATUS_SUCCESS, &created);
        reply(smb2, SMB2_QUERY_DIRECTORY, SMB2_STATUS_ACCESS_DENIED, NULL);
        assert(calls.completed == 1 && smb2->dirs == NULL);
        reply(smb2, SMB2_CLOSE, SMB2_STATUS_SUCCESS, NULL);
        assert(calls.completed == 1);
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

static void cancel_other_open(struct smb2_context *smb2, int status, void *data, void *priv)
{
        struct smb2_pdu **other = priv;
        assert(status < 0);
        smb2_free_pdu(smb2, *other);
        *other = NULL;
}

static void timeout_batch(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_pdu *first, *other, *last;

        smb2->credits = 0;
        smb2_set_timeout(smb2, 10);
        first = smb2_open_async_pdu(smb2, "first", O_RDONLY, cancel_other_open, &other, NULL);
        other = smb2_open_async_pdu(smb2, "second", O_RDONLY, completed, &calls, released);
        last = smb2_open_async_pdu(smb2, "last", O_RDONLY, completed, &calls, NULL);
        assert(first && other && last);
        first->timeout = last->timeout = time(NULL) - 1;
        assert(smb2_service(smb2, 0) == 0);
        assert(!other && calls.released == 1 && calls.completed == 1);
        smb2_free_pdu(smb2, first);
        smb2_free_pdu(smb2, last);
        smb2_set_timeout(smb2, 0);
        smb2->credits = 32;
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
}

static void copy_across_tree_switch(struct smb2_context *smb2)
{
        struct smb2_srv_copychunk chunk = {0};
        struct smb2_ioctl_reply rep = {0};
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        chunk.length = 1;
        assert(smb2_server_side_copy_async(smb2, SMB2_FSCTL_SRV_COPYCHUNK,
                                           fh, fh, &chunk, 1, completed, &calls) == 0);
        rep.output = smb2_alloc_init(smb2, sizeof(struct smb2_srv_copychunk_resume_key));
        assert(rep.output);
        /* reply() selects tree 2 before it dispatches each completion. */
        reply(smb2, SMB2_IOCTL, SMB2_STATUS_SUCCESS, &rep);
        reply(smb2, SMB2_IOCTL, SMB2_STATUS_ACCESS_DENIED, NULL);
        assert(calls.completed == 1);
}

static void seek_during_positioned_io(struct smb2_context *smb2)
{
        struct smb2_write_reply written = {0};
        struct smb2_read_reply read = {0};
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte = 0;

        assert(smb2_select_tree_id(smb2, 1) == 0);
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(!smb2_pwrite_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(smb2_lseek(smb2, fh, 7, SEEK_SET, NULL) == 7);
        written.count = 1;
        reply(smb2, SMB2_WRITE, 0, &written);
        assert(smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) == 7);
        assert(smb2_select_tree_id(smb2, 1) == 0);
        assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(smb2_lseek(smb2, fh, 9, SEEK_SET, NULL) == 9);
        read.data_length = 1;
        reply(smb2, SMB2_READ, 0, &read);
        assert(smb2_lseek(smb2, fh, 0, SEEK_CUR, NULL) == 9);
        assert(calls.completed == 2);
}

static void count_diagnostic(struct smb2_context *smb2, const char *message)
{
        int *count = smb2_get_opaque(smb2);
        (*count)++;
}

static void timed_read_done(struct smb2_context *smb2, int status, void *args, void *priv)
{
        struct smb2_read_cb_data *rd = args;
        struct callbacks *calls = priv;
        int diagnostics = 0;
        assert(status < 0);
        smb2_set_opaque(smb2, &diagnostics);
        smb2_register_error_callback(smb2, count_diagnostic);
        assert(smb2_close(smb2, rd->fh) == -EDEADLK);
        assert(!diagnostics);
        smb2_register_error_callback(smb2, NULL);
        smb2_set_opaque(smb2, NULL);
        calls->completed++;
}

static void timeout_during_sync_wait(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        smb2_set_timeout(smb2, 1);
        assert(fh && !smb2_pread_async(smb2, fh, &byte, 1, 0, timed_read_done, &calls));
        smb2->waitqueue->timeout = time(NULL) - 1;
        assert(smb2_echo(smb2) < 0);
        assert(calls.completed == 1 && !smb2->servicing);
        smb2_set_timeout(smb2, 0);
}

static void close_after_positioned_io(struct smb2_context *smb2)
{
        struct callbacks calls = {0};
        struct smb2_write_reply written = {0};
        smb2_file_id id = {0};
        struct smb2fh *fh;
        uint8_t byte = 0;

        assert(!smb2_select_tree_id(smb2, 1));
        fh = smb2_fh_from_file_id(smb2, &id);
        assert(fh);
        assert(!smb2_pwrite_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(!smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls));
        assert(!smb2_close_async(smb2, fh, completed, &calls));
        assert(smb2_pread_async(smb2, fh, &byte, 1, 0, completed, &calls) == -EBADF);
        assert(smb2->waitqueue->next && !smb2->waitqueue->next->next);
        written.count = 1;
        reply(smb2, SMB2_WRITE, 0, &written);
        assert(calls.completed == 1 && !smb2->waitqueue->next);
        reply(smb2, SMB2_READ, SMB2_STATUS_END_OF_FILE, NULL);
        reply(smb2, SMB2_CLOSE, 0, NULL);
        assert(calls.completed == 3);
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
        directory_query_failure(smb2);
        cancel_symlink_retry(smb2, 0);
        cancel_symlink_retry(smb2, 1);
        assert(smb2_select_tree_id(smb2, 1) == 0);
        owner = smb2_open_async_pdu(smb2, "missing", O_RDONLY,
                                    release_on_completion, &owner, NULL);
        assert(owner);
        reply(smb2, SMB2_CREATE, SMB2_STATUS_OBJECT_NAME_NOT_FOUND, NULL);
        assert(owner == NULL && smb2->fhs == NULL);
        timeout_batch(smb2);
        watch_across_tree_switch(smb2);
        copy_across_tree_switch(smb2);
        seek_during_positioned_io(smb2);
        close_after_positioned_io(smb2);
        timeout_during_sync_wait(smb2);
        disconnect_during_copy(smb2, pair[1]);
        smb2_destroy_context(smb2);
        close(pair[1]);
        return 0;
}
