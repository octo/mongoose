using System;

public class Program {

	// Mongoose object
	static private Mongoose web_server = new Mongoose();

	// This function is called when user types in his browser http://127.0.0.1:8080/foo
	static private void UriHandler(IntPtr conn, ref MongooseRequestInfo ri, IntPtr data) {
		web_server.write(conn, "HTTP/1.1 200 OK\r\n\r\n");
		web_server.write(conn, "Hello from C#!\n");
		web_server.write(conn, "HTTP headers we have received from the browser:\n");
		for (int i = 0; i < ri.num_headers; i++) {
			web_server.write(conn, ri.http_headers[i].name + ": " + ri.http_headers[i].value + "\n");
		}
	}
	
	static void Main() {
		// Set options and /foo URI handler
		web_server.set_option("ports", "8080");
		web_server.set_option("root", "e:\\");
		web_server.bind_to_uri("/foo", new MongooseCallback(UriHandler), IntPtr.Zero);

		// Serve requests until user presses "enter" on a keyboard
		Console.ReadLine();
	}
}