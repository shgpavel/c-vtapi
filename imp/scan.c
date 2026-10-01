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

/* scan: file/scan, scan_big, scan_mem (stdin), rescan, report, clusters,
 * download.  Options act immediately, left to right. */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common.h"

#define MAX_SCAN_SIZE (32 * 1024 * 1024)

/* The handler only records the signal: printing from a signal handler is
 * not async-signal-safe.  "signal caught %d\n" is printed from normal
 * context at the next progress tick or option boundary. */
static volatile sig_atomic_t caught;  /* any SIGHUP/SIGTERM seen */
static volatile sig_atomic_t pending; /* not yet reported, 0 = none */

static void on_signal(int sig) {
	caught = 1;
	pending = sig;
}

static void report_signal(void) {
	int sig = pending;

	if (sig) {
		pending = 0;
		printf("signal caught %d\n", sig);
	}
}

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >   [ --filescan FILE1 ] "
	    "[ --filescan FILE2 ]\n"
	    "  --apikey <API_KEY>         Your virus total API key. This "
	    "arg 1st\n"
	    "  --filescan <FILE>          File to scan, may specify this "
	    "multiple times\n"
	    "  --scaninput [filename]     Scan stdinput.  Scan with buffer "
	    "from ram.\n"
	    "             example:  cat file.bin | scan --apikey ABC "
	    "--scaninput   \n"
	    "  --report <SHA/MD5>          Get a Report on a resource\n"
	    "  --cluster <YYYY-MM-DD>      Get a Report on a resource\n"
	    "  --download <hash>           Output file for download\n"
	    "  --out <file>              Output file for download\n",
	    prog);
}

static int progress(void *ud, int64_t dltotal, int64_t dlnow, int64_t ultotal,
                    int64_t ulnow) {
	(void)ud, (void)dltotal, (void)dlnow;
	report_signal();
	printf("progress_callback %lld/%lld\n", (long long)ulnow,
	       (long long)ultotal);
	/* legacy: once a signal was caught, every later operation is
	 * cancelled too */
	return caught != 0;
}

struct ctx {
	struct vtc_tool t;
	char *out;
	int clusters; /* "Result %d" counter, shared across the run */
	/* legacy: zeroed once, so a report without verbose_msg prints the
	 * previous report's "Msg:" again */
	char msg[256];
};

static vt_err scan_file(struct ctx *x, const char *path, json_t **resp) {
	struct stat st;
	vt_err e;

	if (stat(path, &st)) return VT_EINVAL; /* legacy -1, no request */
	if (st.st_size < 64 * 1024 * 1024)
		return vt_file_scan(x->t.c, path, nullptr, resp);
	e = vt_file_scan_big(x->t.c, path, resp);
	printf(" VtFile_scanBigFile ret =%d \n", vtc_legacy(x->t.c, e));
	return e;
}

static vt_err scan_stdin(struct ctx *x, const char *name, json_t **resp) {
	unsigned char *buf = malloc(MAX_SCAN_SIZE + 1024);
	size_t n;
	vt_err e;

	if (!buf) return VT_ENOMEM;
	n = fread(buf, 1, MAX_SCAN_SIZE, stdin);
	if (n < 1) {
		printf("ERROR %d \n", (int)n);
		free(buf);
		return VT_EINVAL;
	}
	printf("read %d bytes\n", (int)n);
	e = vt_file_scan_mem(x->t.c, name && *name ? name : "filename", buf, n,
	                     nullptr, resp);
	free(buf);
	return e;
}

static void print_clusters(struct ctx *x, const json_t *resp) {
	const json_t *arr = json_object_get(resp, "clusters");
	json_t *el;
	size_t i;

	/* legacy: no "clusters" array is a success without output */
	if (!json_is_array(arr)) return;
	json_array_foreach(arr, i, el) {
		char *s;
		if (!json_is_object(el)) continue;
		printf("------------- Result %d ----------------\n",
		       ++x->clusters);
		s = json_dumps(el, JSON_INDENT(4));
		printf("%s \n", s ? s : "");
		free(s);
		printf("\n");
	}
}

static void download(struct ctx *x, const char *hash) {
	/* legacy: the file is created before the hash is validated */
	FILE *fp = fopen(x->out, "w+");
	vt_err e;

	if (!fp) {
		printf("Error: %d \n", -errno);
		return;
	}
	e = vt_file_download_fp(x->t.c, hash, fp);
	if (fclose(fp) && !e) { /* a failed flush is an error too */
		printf("Error: %d \n", -errno);
		return;
	}
	if (e) printf("Error: %d \n", vtc_legacy(x->t.c, e));
}

static enum vtc_act on_opt(int ch, const char *arg, void *ctxp) {
	struct ctx *x = ctxp;
	json_t *resp = nullptr;
	vt_err e;
	int code;

	if (strchr("fIrcdi", ch)) vtc_require(x->t.have_key, "apikey");
	switch (ch) {
		case 'f':
			e = scan_file(x, arg, &resp);
			vtc_print_result(x->t.c, e, resp);
			break;
		case 'I':
			e = scan_stdin(x, arg, &resp);
			vtc_print_result(x->t.c, e, resp);
			break;
		case 'r':
			e = vt_file_rescan(x->t.c, arg, nullptr, &resp);
			vtc_print_result(x->t.c, e, resp);
			break;
		case 'i':
			e = vt_file_report(x->t.c, arg, &resp);
			vtc_print_result(x->t.c, e, resp);
			if (e) break;
			if (vt_verbose_msg(resp))
				snprintf(x->msg, sizeof x->msg, "%.255s",
				         vt_verbose_msg(resp));
			printf("Msg: %s\n", x->msg);
			if (vt_response_code(resp, &code))
				printf("response code: %d\n", code);
			break;
		case 'c':
			e = vt_file_clusters(x->t.c, arg, &resp);
			if (e)
				printf("Error: %d \n", vtc_legacy(x->t.c, e));
			else
				print_clusters(x, resp);
			break;
		case 'd':
			vtc_require(x->out != nullptr, "out");
			download(x, arg);
			break;
		case 'o':
			vtc_strset(&x->out, arg);
			break;
		case 'h':
			usage(x->t.prog);
			return VTC_STOP;
		default:
			return VTC_UNKNOWN;
	}
	json_decref(resp);
	report_signal();
	return VTC_NEXT;
}

int main(int argc, char *argv[]) {
	static const struct option opts[] = {
	    {"filescan", required_argument, nullptr, 'f'},
	    {"rescan", required_argument, nullptr, 'r'},
	    {"report", required_argument, nullptr, 'i'},
	    {"scaninput", optional_argument, nullptr, 'I'},
	    {"apikey", required_argument, nullptr, 'a'},
	    {"clusters", required_argument, nullptr, 'c'},
	    {"download", required_argument, nullptr, 'd'},
	    {"out", required_argument, nullptr, 'o'},
	    {"verbose", optional_argument, nullptr, 'v'},
	    {"help", optional_argument, nullptr, 'h'},
	    {},
	};
	struct ctx x = {.t.echo_key = true};

	if (!vtc_start(&x.t, argc, argv, usage)) return 0;
	signal(SIGHUP, on_signal);
	signal(SIGTERM, on_signal);
	vt_client_set_progress(x.t.c, progress, nullptr);
	vtc_getopt(&x.t, argc, argv, opts, on_opt, &x);
	report_signal();
	vt_client_free(x.t.c);
	free(x.out);
	return 0;
}
