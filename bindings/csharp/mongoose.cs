//  Copyright (c) 2004-2009 Sergey Lyubka
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//
//  $Id$

using System;
using System.Runtime.InteropServices;


[StructLayout(LayoutKind.Sequential)] public struct MongooseHeader {
	public IntPtr	name;		// Using IntPtr here because if we use strings here,
	public IntPtr	value;		// it won't be properly marshalled.
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
public delegate void MongooseCallback2(IntPtr conn, ref MongooseRequestInfo ri, IntPtr user_data);

// This is a delegate to be used by the application
public delegate void MongooseCallback(MongooseConnection conn, MongooseRequestInfo ri);

public class Mongoose {
	public string version;
	private IntPtr ctx;

	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern IntPtr	mg_start();
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_stop(IntPtr ctx);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_version();
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern int	mg_set_option(IntPtr ctx, string name, string value);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_option(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_bind_to_uri(IntPtr ctx, string uri_regex, MulticastDelegate func, IntPtr data);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_set_log_callback(IntPtr ctx, MulticastDelegate func);

	public Mongoose() {
		ctx = mg_start();
		version = mg_version();
	}

	~Mongoose() {
		mg_stop(this.ctx);
		this.ctx = IntPtr.Zero;
	}

	public int set_option(string option_name, string option_value) {
		return mg_set_option(this.ctx, option_name, option_value);
	}

	public string get_option(string option_name) {
		return mg_get_option(this.ctx, option_name);
	}

	public void bind_to_uri(string uri_regex, MongooseCallback func) {
		// Build a closure around user function. Initialize connection object there which wraps
		// mg_write() and other useful methods, and then call user specified handler.
		MongooseCallback2 callback = delegate(IntPtr conn, ref MongooseRequestInfo ri, IntPtr user_data) {
			MongooseConnection connection = new MongooseConnection(conn, this);
			func(connection, ri);
		};
		mg_bind_to_uri(this.ctx, uri_regex, callback, IntPtr.Zero);
	}
	
	public void set_log_callback(MongooseCallback func) {
		mg_set_log_callback(this.ctx, func);
	}
}

public class MongooseConnection {
	public Mongoose	mongoose;
	private IntPtr conn;

	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_header(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern string	mg_get_var(IntPtr ctx, string name);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] private static extern void	mg_free(IntPtr ptr);
	[DllImport("_mongoose",CallingConvention=CallingConvention.Cdecl)] public static extern int	mg_write(IntPtr conn, string data, int length);

	public MongooseConnection(IntPtr conn_, Mongoose mongoose_) {
		mongoose = mongoose_;
		conn = conn_;
	}

	public string get_header(string header_name) {
		return mg_get_header(this.conn, header_name);
	}

	public string get_var(string header_name) {
		string s = mg_get_var(this.conn, header_name);
		string copy = "" + s;
		mg_free(Marshal.StringToHGlobalAnsi(s));
		return copy;
	}

	public int write(string data) {
		return mg_write(this.conn, data, data.Length);
	}
}
