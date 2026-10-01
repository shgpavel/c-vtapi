/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Code shared by the imp/ command-line tools (and tests/vtprobe.c). */

#ifndef VT_IMP_COMMON_H
#define VT_IMP_COMMON_H 1

#include <getopt.h>

#include "vt/vt.h"

/* Client with no API key and the base URL from $VT_API_BASE_URL (unset or
 * empty: VT_DEFAULT_BASE_URL).  SIGPIPE keeps its default action, as in
 * the legacy tools: a tool whose stdout reader has gone away dies at its
 * next write.  Exits with status 1 if the client cannot be created. */
vt_client *vtc_client(void);

/* The integer the tools print in "Error: %d \n" / "returned error %d\n",
 * as the old library returned it: the HTTP status, the CURLcode (42
 * cancelled, 26 unreadable upload) or -1. */
int vtc_legacy(const vt_client *c, vt_err e);

/* Prints "Response:\n<json_dumps(JSON_INDENT(4))>\n" (nothing for NULL). */
void vtc_print_response(const json_t *resp);

/* "Error: %d \n" with the legacy code on failure, else the response. */
void vtc_print_result(const vt_client *c, vt_err e, const json_t *resp);

/* "Must set --<what> first\n", exit(1) unless `ok`. */
void vtc_require(bool ok, const char *what);

/* free(*dst), then *dst = strdup(v) (NULL for NULL); exit(1) on OOM. */
void vtc_strset(char **dst, const char *v);

/* What every tool has. */
struct vtc_tool {
	const char *prog; /* argv[0] */
	vt_client *c;
	bool echo_key; /* --apikey prints " apikey: %s \n" */
	bool have_key; /* --apikey was given */
};

typedef void vtc_usage_fn(const char *prog);

/* argc < 2: prints usage(argv[0]) and returns false.  Otherwise sets
 * t->prog, creates t->c with vtc_client() and returns true. */
bool vtc_start(struct vtc_tool *t, int argc, char *argv[], vtc_usage_fn *usage);

/* Option handler: return one of these. */
enum vtc_act {
	VTC_NEXT,    /* handled, keep parsing */
	VTC_STOP,    /* stop parsing; skip the non-option listing */
	VTC_UNKNOWN, /* print "?? getopt returned character code 0%o ??" */
};
typedef enum vtc_act vtc_opt_fn(int ch, const char *arg, void *ctx);

/*
 * getopt_long_only(argc, argv, "", opts) loop.  'a' (--apikey, sets the
 * key, echoed if t->echo_key) and 'v' (--verbose[=X]: " verbose
 * selected\n" [+ " verbose level %s \n"]) are handled here; every other
 * value, including '?', goes to fn(ch, optarg, ctx).  Returns -1 if fn
 * returned VTC_STOP, else the number of non-option arguments (after
 * printing "non-option ARGV-elements: " ... when there are any).
 */
int vtc_getopt(struct vtc_tool *t, int argc, char *const argv[],
               const struct option *opts, vtc_opt_fn *fn, void *ctx);

/*
 * The whole ip / domain_report tool: --apikey KEY (echoed), --report ARG
 * (needs --apikey first) runs fn and prints the result, --help prints
 * usage and keeps parsing.  Returns the exit status.
 */
typedef vt_err vtc_report_fn(vt_client *c, const char *arg, json_t **out);
int vtc_report_main(int argc, char *argv[], vtc_usage_fn *usage,
                    vtc_report_fn *fn);

/*
 * The whole file_dist / url_dist tool: --apikey, --limit, --<flag> (sets
 * q.reports), --repeat (default 3), --sleep (default 3 s); then up to
 * --repeat pages with fetch(), stopping at the first error.  `counter`
 * numbers the printed items across pages.  Returns the exit status.
 */
typedef vt_err vtc_dist_fn(vt_client *c, struct vt_dist_query *q, int *counter);
int vtc_dist_main(int argc, char *argv[], vtc_usage_fn *usage, const char *flag,
                  vtc_dist_fn *fetch);

#endif
