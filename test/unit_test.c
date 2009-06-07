#include "../mongoose.c"

static void
fail(const char *fmt, ...)
{
	FILE	*fp = stdout;
	va_list	ap;

	(void) fprintf(fp, "%s", "Unit test: ");

	va_start(ap, fmt);
	(void) vfprintf(fp, fmt, ap);
	va_end(ap);

	fputc('\n', fp);

	exit(EXIT_FAILURE);

}

static void
test_get_var(void)
{
	const char	*post_buffer = "a=b&c=b%2bc&&d=e&f =++g++%%&k=&&";
	const char	*vars[] = {"a", "c", "d", "f ", "k", NULL};
	const char	*vals[] = {"b", "b+c", "e", "  g  %%", ""};
	int		i, buf_len;

	buf_len = strlen(post_buffer);

	for (i = 0; vars[i] != NULL; i++)
		if (strcmp(vals[i], get_var(vars[i], post_buffer, buf_len)))
			fail("%s(%s)", __func__, vars[i]);
}

#if defined(_WIN32)
static void
test_fix_directory_separators(void)
{
	const char	*in[] = {"\\\\server\\\\dir/file.txt",
				"//\\///a", "c:/a//\\\\//////b", NULL};
	const char 	*out[] = {"\\\\server\\dir\\file.txt", "\\\\a",
				"c:\\a\\b"};
	char		buf[FILENAME_MAX];
	int		i;

	for (i = 0; in[i] != NULL; i++) {
		mg_strlcpy(buf, in[i], sizeof(buf));
		fix_directory_separators(buf);
		if (strcmp(buf, out[i]) != 0)
			fail("%s(%s): expected [%s], got [%s]",
			    __func__, in[i], out[i], buf);
	}
}
#else
#define	test_fix_directory_separators()
#endif /* _WIN32 */

/*
 * Test function that converts requested URI to the full path.
 * Since make_path honours aliases option, this also tests aliases.
 */
static void
test_make_path(void)
{
#if defined(_WIN32)
#define	SLASH	"\\"
#else
#define	SLASH	"/"
#endif
	struct {char *uri, *aliases, *root, *result;} tests[] = {
		{"/", "", "/", SLASH SLASH },
		{"/xyz", "/x=/y", "/", SLASH "yyz"},
		{"/xyz", "/x/=/y", "/", SLASH SLASH "xyz"},
		{"/xyz", "/x/=/y", "/boo", SLASH "boo" SLASH "xyz"},
		{"/", "/x=/y", "/foo", SLASH "foo" SLASH},
		{"/x/y/z", "/a=/b,/x=/y,/c=/d", "/foo",
			SLASH "y" SLASH "y" SLASH "z"},
		{NULL, NULL, NULL, NULL},
	};

	char		buf[FILENAME_MAX];
	int		i;
	struct mg_context	*ctx;

	ctx = mg_start();

	/* Loop through all URIs, making paths and comparing with expected. */
	for (i = 0; tests[i].uri != NULL; i++) {
		(void) mg_set_option(ctx, "root", tests[i].root);
		(void) mg_set_option(ctx, "aliases", tests[i].aliases);

		/* Convert URI to the full file name */
		convert_uri_to_file_name(fc(ctx),
				tests[i].uri, buf, sizeof(buf));

		/* Fail if the result is not what we expect */
		if (strcmp(buf, tests[i].result) != 0)
			fail("%s(%s): expected [%s], got [%s]",
			    __func__, tests[i].uri, tests[i].result, buf);
	}

	mg_stop(ctx);
}

static void
test_set_option(void)
{
	struct {
		const char	*opt_name;	/* Option name		*/
		const char	*opt_value;	/* Option value		*/
		int result;			/* Expected result	*/
	} tests[] = {
		{"aliases", "a,b,c", 0},	/* Zero length value	*/
		{"aliases", "a=,b=c,c=d", 0},	/* Zero length value	*/
		{"aliases", "=a,b=c,c=d", 0},	/* Zero length key	*/
		{"aliases", "a=b,b=c,c=d", 1},	/* OK */
		{"not_existent_option", "", -1}, /* Unknown option */
		{NULL, NULL, 0}
	};

	struct mg_context	*ctx;
	int			i;

	ctx = mg_start();
	for (i = 0; tests[i].opt_name != NULL; i++) {
		if (mg_set_option(ctx, tests[i].opt_name,
		    tests[i].opt_value) != tests[i].result)
			fail("%s: mg_set_option(%s): failed expectation",
			    __func__, tests[i].opt_name);
	}
	mg_stop(ctx);
}

test_parse_http_request(void)
{
	struct mg_request_info	ri;
	struct usa		usa;

	char	empty[] = "";
	char	bad1[] = "BOO / HTTP/1.0\n\n";
	char	bad2[] = "GET / TTP/1.0\n\n";
	char	bad3[] = "GET TTP/1.0\n\n";
	char	bad4[] = "GET \n/ HTTP/1.0\n\n";
	char	good[] = "GET / HTTP/1.0\n\n";
	char	good2[] = "GET / HTTP/1.1\r\nA: b c\nB: c d\r\nC:  \r\n\n";

	if (parse_http_request(empty, &ri, &usa) != FALSE)
		fail("%s: empty request", __func__);

	if (parse_http_request(bad1, &ri, &usa) != FALSE ||
	    parse_http_request(bad2, &ri, &usa) != FALSE ||
	    parse_http_request(bad3, &ri, &usa) != FALSE ||
	    parse_http_request(bad4, &ri, &usa) != FALSE)
		fail("%s: bad request parsed successfully", __func__);

	if (parse_http_request(good, &ri, &usa) != TRUE)
		fail("%s: good request", __func__);

	if (parse_http_request(good2, &ri, &usa) != TRUE ||
	    ri.num_headers != 3 ||
	    strcmp(ri.http_headers[0].name, "A") != 0 ||
	    strcmp(ri.http_headers[0].value, "b c") != 0 ||
	    strcmp(ri.http_headers[1].name, "B") != 0 ||
	    strcmp(ri.http_headers[1].value, "c d") != 0 ||
	    strcmp(ri.http_headers[2].name, "C") != 0 ||
	    strcmp(ri.http_headers[2].value, "") != 0)
		fail("%s: good2 request", __func__);

}

int main(int argc, char *argv[])
{
	test_get_var();
	test_fix_directory_separators();
	test_make_path();
	test_set_option();
	test_parse_http_request();

	return (EXIT_SUCCESS);
}
