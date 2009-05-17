using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// This is "struct mg_header" from mongoose.h header file
[StructLayout(LayoutKind.Sequential)] public struct MongooseHeader {
	public string	name;
	public string	value;
};

// This is "struct mg_request_info" from mongoose.h header file
[StructLayout(LayoutKind.Sequential)] public struct MongooseRequestInfo {
	public string	request_method;
	public string	uri;
	public string	post_data;
	public string	remote_user;
	public long	remote_ip;
	public int	remote_port;
	public int	post_data_len;
	public int	http_version_major;
	public int	http_version_minor;
	public int	status_code;
	public int	num_headers;
	[MarshalAs(UnmanagedType.ByValArray,SizeConst=64)] public MongooseHeader[] http_headers;
};

// This is a delegate for mg_callback_t from mongoose.h header file
public delegate void MongooseCallback(IntPtr conn, ref MongooseRequestInfo ri, IntPtr user_data);

public class Mongoose {
	public string version;
	private IntPtr ctx;

	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr	mg_start();
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_stop(IntPtr ctx);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_version();
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern int	mg_set_option(IntPtr ctx, string name, string value);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_option(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_header(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_var(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_free(IntPtr ptr);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_get_option_list(IntPtr ctx);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern int	mg_write(IntPtr conn, string data, int length);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_bind_to_uri(IntPtr ctx, string uri_regex, MulticastDelegate func, IntPtr data);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_set_log_callback(IntPtr ctx, MulticastDelegate func);

	public Mongoose() {
		ctx = mg_start();
		version = mg_version();
	}
	
	public int set_option(string option_name, string option_value) {
		return mg_set_option(this.ctx, option_name, option_value);
	}

	public string get_option(string option_name) {
		return mg_get_option(this.ctx, option_name);
	}
	
	public string get_header(IntPtr conn, string header_name) {
		return mg_get_header(conn, header_name);
	}
	
	public int write(IntPtr conn, string data) {
		return mg_write(conn, data, data.Length);
	}

	public void bind_to_uri(string uri_regex, MongooseCallback func, IntPtr data) {
		mg_bind_to_uri(this.ctx, uri_regex, func, data);
	}
	
	public void set_log_callback(MongooseCallback func) {
		mg_set_log_callback(this.ctx, func);
	}

}