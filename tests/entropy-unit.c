/* Context setup with a custom random provider. LGPL-2.1-or-later. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "smb2.h"
#include "libsmb2.h"

static int ready;
static int draws;

static int test_random(void *buf, size_t len)
{
        if (!ready) {
                return EAGAIN;
        }
        memset(buf, ++draws, len);
        return 0;
}

int main(void)
{
        struct smb2_context *smb2 = NULL;
        smb2_set_random_provider(test_random);
        assert(smb2_init_context() == NULL && errno == EAGAIN);
        ready = 1;
        smb2 = smb2_init_context();
        assert(smb2 != NULL && draws > 0);
        smb2_destroy_context(smb2);
        smb2_set_random_provider(NULL);
        return 0;
}
