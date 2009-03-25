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



int main(int argc, char *argv[])
{
	test_get_var();
	test_fix_directory_separators();

	return (EXIT_SUCCESS);
}
