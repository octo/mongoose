#include "../mongoose.c"

static void
fail(const char *fmt, ...)
{
	va_list	ap;

	(void) fprintf(stderr, "%s", "Unit test: ");

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);

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
		{"/x/y/z", "/a=/b,,/x=/y,/c=/d", "/foo",
			SLASH "y" SLASH "y" SLASH "z"},
		{NULL, NULL, NULL, NULL},
	};
	char		buf[FILENAME_MAX];
	int		i;
	struct mg_context	fake_context;

	/* make_path() locks the options mutex, so initialize it before */
	pthread_mutex_init(&fake_context.opt_mutex[OPT_ROOT], NULL);
	pthread_mutex_init(&fake_context.opt_mutex[OPT_ALIASES], NULL);

	/* Loop through all URIs, making paths and comparing with expected. */
	for (i = 0; tests[i].uri != NULL; i++) {
		fake_context.options[OPT_ROOT] = tests[i].root;
		fake_context.options[OPT_ALIASES] = tests[i].aliases;

		/* Convert URI to the full file name */
		make_path(&fake_context, tests[i].uri, buf, sizeof(buf));

		/* Fail if the result is not what we expect */
		if (strcmp(buf, tests[i].result) != 0)
			fail("%s(%s): expected [%s], got [%s]",
			    __func__, tests[i].uri, tests[i].result, buf);
	}

	/* Cleanup - destroy the mutex */
	pthread_mutex_destroy(&fake_context.opt_mutex[OPT_ROOT]);
	pthread_mutex_destroy(&fake_context.opt_mutex[OPT_ALIASES]);
}

int main(int argc, char *argv[])
{
	test_get_var();
	test_fix_directory_separators();
	test_make_path();

	return (EXIT_SUCCESS);
}
