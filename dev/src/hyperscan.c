#include <stdio.h>
#include <stdlib.h>

#include <hs.h>

#include "hyperscan.h"

#define MAX_PATTERN_NUM  256
#define MAX_FLOW_NUM     4096

#define PCRE_FILE_NAME   "grep.txt"

char *g_pattern[MAX_PATTERN_NUM];
unsigned int g_ids[MAX_PATTERN_NUM];
unsigned int g_flags[MAX_PATTERN_NUM];

hs_database_t *g_database;
hs_scratch_t  *g_scratch;
hs_stream_t   *g_streams[MAX_FLOW_NUM];

static int parse_pcre_file(void);

/**
 * This is the function that will be called for each match that occurs. @a ctx
 * is to allow you to have some application-specific state that you will get
 * access to for each match. In our simple example we're just going to use it
 * to pass in the pattern that was being searched for so we can print it out.
 */
static int eventHandler(unsigned int id, unsigned long long from,
        unsigned long long to, unsigned int flags, void *ctx)
{
    printf("Match for pattern \"%d\" at offset %llu\n", id, to);

    struct matched_data *mdata = (struct matched_data *)ctx;
    rte_hash_add_key_with_hash(mdata->handle, mdata->tuple, mdata->hash);

    return 0;
}


int hyperscan_init(void)
{
    int rules = 0;
    int i = 0, ret = 0;
    hs_compile_error_t *compile_err = NULL;

        rules = parse_pcre_file();

    /* First, we attempt to compile the pattern provided on the command line.
     * We assume 'DOTALL' semantics, meaning that the '.' meta-character will
     * match newline characters. The compiler will analyse the given pattern and
     * either return a compiled Hyperscan database, or an error message
     * explaining why the pattern didn't compile.
     */
    if (hs_compile_multi(g_pattern, g_flags, g_ids, rules,
                 HS_MODE_STREAM, NULL, &g_database, &compile_err) != HS_SUCCESS) {
        if (compile_err->expression < 0) {
            // The error does not refer to a particular expression.
            printf("error:%s \n", compile_err->message);
        } else {
            printf("error:pattern %s \n", g_pattern[compile_err->expression]);
            printf(" failed compilation with error: %s", compile_err->message);
        }
        hs_free_compile_error(compile_err);

        return -1;
    }

    /* Finally, we issue a call to hs_scan, which will search the input buffer
     * for the pattern represented in the bytecode. Note that in order to do
     * this, scratch space needs to be allocated with the hs_alloc_scratch
     * function. In typical usage, you would reuse this scratch space for many
     * calls to hs_scan, but as we're only doing one, we'll be allocating it
     * and deallocating it as soon as our matching is done.
     *
     * When matches occur, the specified callback function (eventHandler in
     * this file) will be called. Note that although it is reminiscent of
     * asynchronous APIs, Hyperscan operates synchronously: all matches will be
     * found, and all callbacks issued, *before* hs_scan returns.
     *
     * In this example, we provide the input pattern as the context pointer so
     * that the callback is able to print out the pattern that matched on each
     * match event.
     */
    if (hs_alloc_scratch(g_database, &g_scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        hs_free_database(g_database);

        return -1;
    }

    for (i = 0; i < MAX_FLOW_NUM; i++) {
        ret = hs_open_stream(g_database, 0, &g_streams[i]);
        if (ret) {
            fprintf(stderr, "ERROR: Unable to open stream space. Exiting.\n");
            hs_free_database(g_database);

            return -1;
        }
    }

    return 0;
}

int hyperscan_destroy(void)
{
    int ret = 0, i = 0;

    /* Scanning is complete, any matches have been handled, so now we just
     * clean up and exit.
     */
    for (i = 0; i < MAX_FLOW_NUM; i++) {
        if (hs_close_stream(g_streams[i], g_scratch, NULL, NULL) != HS_SUCCESS) {
            fprintf(stderr, "ERROR: hs_close_stream error.\n");
            ret = -1;

        goto Error;
        }
    }

Error:
    hs_free_scratch(g_scratch);
    hs_free_database(g_database);

    return ret;
}

int hyperscan_scan(struct rte_mbuf *m, struct matched_data *m_data)
{
    if (hs_scan_stream(g_streams[m_data->hash % 4096], rte_pktmbuf_mtod(m, char *),
                       rte_pktmbuf_data_len(m), 0, g_scratch, eventHandler, m_data) != HS_SUCCESS) {
    fprintf(stderr, "hs_scan_stream error.\n");

    return -1;
    }

    return 0;
}

static int parse_pcre_file(void)
{
        int idx, i;

    FILE *fp     = NULL;
    char *lbuf   = NULL;
    size_t lsize = 0;
    int ret = 0;

        fp = fopen(PCRE_FILE_NAME, "r");
        if (!fp) {
             return -1;
        }

        for (i = 0; (ret = getline(&lbuf, &lsize, fp)) > 0; i++) {
        g_pattern[i] = (char *)calloc(1, strlen(lbuf) + 1);
                sscanf(lbuf, "%d%*2c%[^/]", &idx, g_pattern[i]);
        g_ids[i] = idx;
        g_flags[i] = HS_FLAG_DOTALL;
        printf("idx=%d, pattern=%s\n", idx, g_pattern[i]);
        }
        free(lbuf);

    return i - 1;
}

