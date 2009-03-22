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
			fail("get_var(%s)", vars[i]);
}


int main(int argc, char *argv[])
{
	test_get_var();

	return (EXIT_SUCCESS);
}
