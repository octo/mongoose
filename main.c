/*
 * Copyright (c) 2004-2009 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "mongoose.h"

#ifdef _WIN32
#define DIRSEP	'\\'
#else
#include <sys/wait.h>
#include <unistd.h>		/* For pause() */
#define DIRSEP '/'
#endif /* _WIN32 */

static int  exit_flag;	                /* Program termination flag	*/
static struct mg_context	*ctx;   /* Mongoose context		*/

static void
signal_handler(int sig_num)
{
	switch (sig_num) {
#ifndef _WIN32
	case SIGCHLD:
		while (waitpid(-1, &sig_num, WNOHANG) > 0) ;
		break;
#endif /* !_WIN32 */
	default:
		exit_flag = sig_num;
                if (ctx != NULL)
                    mg_stop(ctx);
		break;
	}
}

/*
 * Show usage string and exit.
 */
static void
show_usage_and_exit(const char *prog)
{
	const struct mg_option	*o;

	(void) fprintf(stderr,
	    "Mongoose version %s (c) Sergey Lyubka\n"
	    "usage: %s [options] [config_file]\n", mg_version(), prog);

#if !defined(NO_AUTH)
	fprintf(stderr, "  -A <htpasswd_file> <realm> <user> <passwd>\n");
#endif /* NO_AUTH */

	o = mg_get_option_list();
	for (; o->name != NULL; o++) {
		(void) fprintf(stderr, "  -%s\t%s", o->name, o->description);
		if (o->default_value != NULL)
			fprintf(stderr, " (default: \"%s\")", o->default_value);
		fputc('\n', stderr);
	}
	exit(EXIT_FAILURE);
}

#if !defined(NO_AUTH)
/*
 * Edit the passwords file.
 */
static int
mg_edit_passwords(const char *fname, const char *domain,
		const char *user, const char *pass)
{
	int	ret = EXIT_SUCCESS, found = 0;
	char	line[512], u[512], d[512], ha1[33], tmp[FILENAME_MAX];
	FILE	*fp = NULL, *fp2 = NULL;

	(void) snprintf(tmp, sizeof(tmp), "%s.tmp", fname);

	/* Create the file if does not exist */
	if ((fp = fopen(fname, "a+")))
		(void) fclose(fp);

	/* Open the given file and temporary file */
	if ((fp = fopen(fname, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s: %s", fname, strerror(errno));
                exit(EXIT_FAILURE);
        } else if ((fp2 = fopen(tmp, "w+")) == NULL) {
		fprintf(stderr, "Cannot open %s: %s", tmp, strerror(errno));
                exit(EXIT_FAILURE);
        }

	/* Copy the stuff to temporary file */
	while (fgets(line, sizeof(line), fp) != NULL) {

		if (sscanf(line, "%[^:]:%[^:]:%*s", u, d) != 2)
			continue;

		if (!strcmp(u, user) && !strcmp(d, domain)) {
			found++;
			mg_md5(ha1, user, ":", domain, ":", pass, NULL);
			(void) fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
		} else {
			(void) fprintf(fp2, "%s", line);
		}
	}

	/* If new user, just add it */
	if (!found) {
		mg_md5(ha1, user, ":", domain, ":", pass, NULL);
		(void) fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
	}

	/* Close files */
	(void) fclose(fp);
	(void) fclose(fp2);

	/* Put the temp file in place of real file */
	(void) remove(fname);
	(void) rename(tmp, fname);

	return (ret);
}
#endif /* NO_AUTH */

static void
process_command_line_arguments(struct mg_context *ctx, char *argv[])
{
	const char	*config_file = "mongoose.conf";
	char		line[BUFSIZ], opt[BUFSIZ],
				val[BUFSIZ], path[FILENAME_MAX], *p;
	FILE		*fp;
	size_t		i, line_no = 0;

	/* First find out, which config file to open */
	for (i = 1; argv[i] != NULL && argv[i][0] == '-'; i += 2)
		if (argv[i + 1] == NULL)
			show_usage_and_exit(argv[0]);

	if (argv[i] != NULL && argv[i + 1] != NULL) {
		/* More than one non-option arguments are given w*/
		show_usage_and_exit(argv[0]);
	} else if (argv[i] != NULL) {
		/* Just one non-option argument is given, this is config file */
		config_file = argv[i];
	} else {
		/* No config file specified. Look for one where binary lives */
		if ((p = strrchr(argv[0], DIRSEP)) != 0) {
			snprintf(path, sizeof(path), "%.*s%s",
			    p - argv[0] + 1, argv[0], config_file);
			config_file = path;
		}
	}

	fp = fopen(config_file, "r");

	/* If config file was set in command line and open failed, exit */
	if (fp == NULL && argv[i] != NULL) {
		(void) fprintf(stderr, "cannot open config file %s: %s\n",
		    config_file, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fp != NULL) {
		(void) printf("Loading config file %s\n", config_file);

		/* Loop over the lines in config file */
		while (fgets(line, sizeof(line), fp) != NULL) {

			line_no++;

			/* Ignore empty lines and comments */
			if (line[0] == '#' || line[0] == '\n')
				continue;

			if (sscanf(line, "%s %[^\n#]", opt, val) != 2) {
				fprintf(stderr, "%s: line %d is invalid\n",
				    config_file, (int) line_no);
				exit(EXIT_FAILURE);
			}

			if (mg_set_option(ctx, opt, val) != 1) {
				(void) fprintf(stderr,
				    "Error setting option \"%s\"\n", opt);
				exit(EXIT_FAILURE);
			}
		}

		(void) fclose(fp);
	}

	/* Now pass through the command line options */
	for (i = 1; argv[i] != NULL && argv[i][0] == '-'; i += 2)
		if (mg_set_option(ctx,
		    &argv[i][1], argv[i + 1]) != 1) {
			(void) fprintf(stderr,
			    "Error setting option \"%s\"\n", &argv[i][1]);
			exit(EXIT_FAILURE);
		}
}

int
main(int argc, char *argv[])
{
#if !defined(NO_AUTH)
	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'A') {
		if (argc != 6)
			show_usage_and_exit(argv[0]);
		exit(mg_edit_passwords(argv[2], argv[3], argv[4],argv[5]));
	}
#endif /* NO_AUTH */

	if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
		show_usage_and_exit(argv[0]);

#if defined(_WIN32)
	try_to_run_as_nt_service();
#endif /* _WIN32 */

#ifndef _WIN32
	(void) signal(SIGCHLD, signal_handler);
	(void) signal(SIGPIPE, SIG_IGN);
#endif /* _WIN32 */

	(void) signal(SIGTERM, signal_handler);
	(void) signal(SIGINT, signal_handler);

	if ((ctx = mg_start()) == NULL) {
		(void) printf("%s\n", "Cannot initialize Mongoose context");
		exit(EXIT_FAILURE);
	}

	process_command_line_arguments(ctx, argv);
	if (mg_get_option(ctx, "ports") == NULL)
		mg_set_option(ctx, "ports", "8080");

	printf("Mongoose %s started on port(s) [%s], serving directory [%s]\n",
			mg_version(),
			mg_get_option(ctx, "ports"),
			mg_get_option(ctx, "root"));
	fflush(stdout);
	while (exit_flag == 0)
		pause();
	(void) printf("Exit on signal %d\n", exit_flag);

	return (EXIT_SUCCESS);
}
