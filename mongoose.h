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

#ifndef MONGOOSE_HEADER_INCLUDED
#define	MONGOOSE_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct mg_context;		/* Handle for the HTTP service itself	*/
struct mg_connection;	/* Handle for the individual connection	*/

/*
 * This structure contains full information about the HTTP request.
 * It is passed to the user-specified callback function as a parameter.
 */
struct mg_request_info {
	const char	*request_method;	/* "GET", "POST", etc	*/
	const char	*uri;			/* Normalized URI	*/
	const char	*query_string;		/* \0 - terminated	*/
	const char	*post_data;		/* POST data buffer	*/
	const char	*remote_user;		/* Authenticated user	*/
	unsigned long	remote_ip;		/* Client's IP address	*/
	int		remote_port;		/* Client's port	*/
	int		post_data_len;		/* POST buffer length	*/
	int		http_version_major;
	int		http_version_minor;
	int		num_headers;		/* Number of headers	*/
#define	MAX_HTTP_HEADERS	64
	struct mg_header {
		const char	*name;		/* HTTP header name	*/
		const char	*value;		/* HTTP header value	*/
	} http_headers[MAX_HTTP_HEADERS];
};

/*
 * User-defined function prototype.
 * It is passed opaque connection handle, and request information structure.
 */
typedef void (*mg_callback_t)(struct mg_connection *,
		const struct mg_request_info *info, void *user_data);

/*
 * Functions dealing with initialization, starting and stopping Mongoose
 *
 * mg_start		Start serving thread. Make and returns server context.
 * mg_stop		Stop server thread, and release the context.
 * mg_set_option	Set an option for the running context.
 * mg_get_option	Get an option for the running context.
 * mg_get_option_list	Get a list of all known options.
 * mg_bind		Associate user function with URI, or error, or SSI.
 *			Passing NULL as function pointer means un-bind.
 *			'*' in regex matches zero or more characters.
 */

struct mg_context *mg_start(void);
void mg_stop(struct mg_context *);

/*
 * Altering Mongoose configuration:
 * Getting list of all available options and their descriptions,
 * getting current value of an option, and setting new value.
 */
struct mg_option {
	const char	*name;
	const char	*description;
	const char	*default_value;
};
const struct mg_option *mg_get_option_list(void);
const char *mg_get_option(struct mg_context *, const char *);
int mg_set_option(struct mg_context *, const char *, const char *);

/*
 * User-defined function can be bound to the particular URI,
 * or HTTP error code, or SSI keyword. In all cases, wildcards can be used,
 * where '*' stands for 'zero or more characters'.
 */
enum mg_bind_target {BIND_TO_URI, BIND_TO_ERROR_CODE, BIND_TO_SSI_KEYWORD};
void mg_bind(struct mg_context *ctx, enum mg_bind_target,
		const char *regex, mg_callback_t func, void *user_data);

/*
 * Functions that can be used within the user URI callback
 *
 * mg_write	Send data to the remote end.
 * mg_printf	Send data, using printf() semantics.
 * mg_get_header Helper function to get HTTP header value
 * mg_get_var	Helper function to get form variable value.
 *		Returned value must be free-d by the caller.
 * mg_version	Return current version.
 * mg_md5	Helper function. buf must be 33 bytes in size. Expects
 *		a NULL terminated list of asciz strings.
 *		Fills buf with stringified \0 terminated MD5 hash.
 */
int mg_write(struct mg_connection *, const void *buf, int len);
int mg_printf(struct mg_connection *, const char *fmt, ...);
const char *mg_get_header(const struct mg_connection *, const char *);
char *mg_get_var(const struct mg_connection *, const char *);
const char *mg_version(void);
void mg_md5(char *buf, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MONGOOSE_HEADER_INCLUDED */
