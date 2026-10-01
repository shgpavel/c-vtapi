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

/* domain_report: GET domain/report. */

#include <stdio.h>

#include "common.h"

static void usage(const char *prog) {
	printf(
	    "%s < --apikey YOUR_API_KEY >  < --report  example.com --> \n"
	    "  --apikey YOUR_API_KEY   Your virus total API key.  This arg "
	    "1st \n"
	    "  --report      get report for IP Address\n"
	    "  --verbose     be verbose\n"
	    "  --help        print this help message\n",
	    prog);
}

int main(int argc, char *argv[]) {
	return vtc_report_main(argc, argv, usage, vt_domain_report);
}
