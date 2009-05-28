// This is C# example on how to use Mongoose embeddable web server,
// http://code.google.com/p/mongoose
//
// Before using the mongoose module, make sure that Mongoose shared library is
// built and present in the current (or system library) directory

using System;

public class Program {

	// This function is called when user types in his browser http://127.0.0.1:8080/foo
	static private void UriHandler(MongooseConnection conn, MongooseRequestInfo ri) {
		conn.write("HTTP/1.1 200 OK\r\n\r\n");
		conn.write("Hello from C#!\n");
		conn.write("Your user-agent is: " + conn.get_header("User-Agent") + "\n");
	}

	static void Main() {
		Mongoose web_server = new Mongoose();

		// Set options and /foo URI handler
		web_server.set_option("ports", "8080");
		web_server.set_option("root", "c:\\");
		web_server.set_uri_callback("/foo", new MongooseCallback(UriHandler));

		// Serve requests until user presses "enter" on a keyboard
		Console.ReadLine();
	}
}
