#!/usr/bin/env perl
# This script is used to test Mongoose web server
# $Id$

use IO::Socket;
use strict;
use warnings;
use diagnostics;

my $port = 23456;
my $pid = undef;
my $num_requests;
my $root = 'test';
my $test_dir_uri = "test_dir";
my $test_dir = "$root/$test_dir_uri";
my $alias = "/aliased=/etc/,/ta=$test_dir";
my $config = 'mongoose.conf';
my $exe = './mongoose';
my $embed_exe = './embed';
my $exit_code = 0;

my @files_to_delete = ('debug.log', 'access.log', $config, "$root/put.txt",
	"$test_dir/index.html", "$test_dir/env.cgi",
	"$root/binary_file", $embed_exe);

END {
	unlink @files_to_delete;
	rmdir $test_dir;
	kill_spawned_child();
	exit $exit_code;
}

sub fail {
	print "FAILED: @_\n";
	$exit_code = 1;
	exit 1;
}

sub get_num_of_log_entries {
	open FD, "access.log"; my @logs = (<FD>); close FD;
	return scalar @logs;
}

# Send the request to the 127.0.0.1:$port and return the reply
sub req {
	my ($request, $inc) = @_;
	my $sock = IO::Socket::INET->new(Proto=>"tcp",
		PeerAddr=>'127.0.0.1', PeerPort=>$port);
	fail("Cannot connect: $!") unless $sock;
	$sock->autoflush(1);
	foreach (split //, $request) {
		print $sock $_;
		select undef, undef, undef, .001 if length($request) < 256;
	}
	my @lines = <$sock>;
	my $out = join '', @lines;
	close $sock;

	$num_requests += defined($inc) ? $inc : 1;
	my $num_logs = get_num_of_log_entries();

	unless ($num_requests == $num_logs) {
		fail("Request has not been logged: [$request]")
	}

	return $out;
}

# Send the request. Compare with the expected reply. Fail if no match
sub o {
	my ($request, $expected_reply, $message, $num_logs) = @_;
	print "$message ... ";
	my $reply = req($request, $num_logs);
	if ($reply =~ /$expected_reply/s) {
		print "OK\n";
	} else {
		fail("Expected: [$expected_reply], got: [$reply]");
	}
}

# Spawn a server listening on specified port
sub spawn {
	unless ($pid = fork()) {
		exec @_;
		die "cannot exec: $!\n";
	}
	sleep 1;
}

sub read_file {
	open FD, $_[0] or fail "Cannot open $_[0]: $!";
	my @lines = <FD>;
	close FD;
	return join '', @lines;
}

sub kill_spawned_child {
	kill(9, $pid) && waitpid($pid, 0) if defined($pid);
}

####################################################### ENTRY POINT

unlink @files_to_delete;
$SIG{PIPE} = 'IGNORE';
#local $| =1;

# Make sure we export only symbols that start with "mg_", and keep local
# symbols static.
if ($^O =~ /darwin|bsd|linux/) {
	my $out = `(cc -c mongoose.c && nm mongoose.o) | grep ' T '`;
	foreach (split /\n/, $out) {
		/T\s+_?mg_.+/ or fail("Exported symbol $_")
	}
}

# Make sure we load config file if no options are given
open FD, ">$config";
print FD "ports 12345\naccess_log access.log\n";
close FD;
spawn($exe);
my $saved_port = $port;
$port = 12345;
o("GET /test/hello.txt HTTP/1.0\n\n", 'HTTP/1.1 200 OK', 'Loading config file');
$port = $saved_port;
unlink $config;
kill_spawned_child();

# Spawn the server on port $port
spawn("$exe -ports $port -access_log access.log -error_log debug.log ".
		"-root test ".
		"-aliases $alias -auth_PUT test/passfile");

# Try to overflow: Send very long request
req('POST ' . '/..' x 100 . 'ABCD' x 3000 . "\n\n", 0); # don't log this one

o("GET /hello.txt HTTP/1.0\n\n", 'HTTP/1.1 200 OK', 'GET regular file');
o("GET /%68%65%6c%6c%6f%2e%74%78%74 HTTP/1.0\n\n",
	'HTTP/1.1 200 OK', 'URL-decoding');

# Test HTTP version parsing
o("GET / HTTPX/1.0\r\n\r\n", '400 Bad Request', 'Bad HTTP Version', 0);
o("GET / HTTP/x.1\r\n\r\n", '400 Bad Request', 'Bad HTTP maj Version', 0);
o("GET / HTTP/1.1z\r\n\r\n", '400 Bad Request', 'Bad HTTP min Version', 0);
o("GET / HTTP/02.0\r\n\r\n", '505 HTTP version not supported',
	'HTTP Version >1.1');

mkdir $test_dir unless -d $test_dir;
o("GET /$test_dir_uri/not_exist HTTP/1.0\n\n",
	'HTTP/1.1 404', 'PATH_INFO loop problem');
o("GET /$test_dir_uri HTTP/1.0\n\n", 'HTTP/1.1 301', 'Directory redirection');
o("GET /$test_dir_uri/ HTTP/1.0\n\n", 'Modified', 'Directory listing');
open FD, ">$test_dir/index.html"; print FD "tralala"; close FD;
o("GET /$test_dir_uri/ HTTP/1.0\n\n", 'tralala', 'Index substitution');
o("GET /ta/ HTTP/1.0\n\n", 'Modified', 'Aliases');
o("GET /not-exist HTTP/1.0\r\n\n", 'HTTP/1.1 404', 'Not existent file');
o("GET /hello.txt HTTP/1.1\n\nGET /hello.txt HTTP/1.0\n\n",
	'HTTP/1.1 200.+keep-alive.+HTTP/1.1 200.+close',
	'Request pipelining', 2);


my $mime_types = {
	html => 'text/html',
	htm => 'text/html',
	txt => 'text/plain',
	unknown_extension => 'text/plain',
	js => 'application/x-javascript',
	css => 'text/css',
	jpg => 'image/jpeg',
};

foreach my $key (keys %$mime_types) {
	my $filename = "_mime_file_test.$key";
	open FD, ">$root/$filename";
	close FD; 
	o("GET /$filename HTTP/1.0\n\n",
		"Content-Type: $mime_types->{$key}", ".$key mime type");
	unlink "$root/$filename";
}

# Get binary file and check the integrity
my $binary_file = 'binary_file';
my $f2 = ''; 
foreach (0..123456) { $f2 .= chr(int(rand() * 255)); }
open FD, ">$root/$binary_file";
binmode FD;
print FD $f2;
close FD;
my $f1 = req("GET /$binary_file HTTP/1.0\r\n\n");
while ($f1 =~ /^.*\r\n/) { $f1 =~ s/^.*\r\n// }
$f1 eq $f2 or fail("Integrity check for downloaded binary file");

my $out = req("GET /hello.txt HTTP/1.1\nConnection: close\n".
		"Range: bytes=3-5\r\n\r\n");
$out =~ /206 Partial Content/ or fail("Partial Content not seen ($out)");
$out =~ /Content-Length: 3/ or fail("Bad Range length ($out)");
$out =~ /Content-Range: bytes 3-5/ or fail("Bad Range ($out)");
$out =~ /\nple$/s or fail("Bad Range content ($out)");
print "Range support ... OK\n";

unless (scalar(@ARGV) > 0 and $ARGV[0] eq "basic_tests") {
	o("GET /env.cgi HTTP/1.0\n\r\n", 'HTTP/1.1 200 OK', 'GET CGI file');
	o("GET /env.cgi?var=HELLO HTTP/1.0\n\n", 'QUERY_STRING=var=HELLO',
		'QUERY_STRING wrong');
	o("POST /env.cgi HTTP/1.0\r\nContent-Length: 9\r\n\r\nvar=HELLO",
		'var=HELLO', 'CGI POST wrong');
	o("POST /env.cgi HTTP/1.0\r\nContent-Length: 9\r\n\r\nvar=HELLO",
	'\x0aCONTENT_LENGTH=9', 'Content-Length not being passed to CGI');
	o("GET /env.cgi HTTP/1.0\nMy-HdR: abc\n\r\n",
		'HTTP_MY_HDR=abc', 'HTTP_* env');
	o("GET /env.cgi HTTP/1.0\n\r\nSOME_TRAILING_DATA_HERE",
		'HTTP/1.1 200 OK', 'GET CGI with trailing data');

	my $auth_header = "Authorization: Digest  username=guest, ".
		"realm=mydomain.com, nonce=1145872809, uri=/put.txt, ".
		"response=896327350763836180c61d87578037d9, qop=auth, ".
		"nc=00000002, cnonce=53eddd3be4e26a98\n";

	o("PUT /put.txt HTTP/1.0\nContent-Length: 7\n$auth_header\n1234567",
		"HTTP/1.1 201 OK", 'PUT file, status 201');
	fail("PUT content mismatch")
		unless read_file("$root/put.txt") eq '1234567';
	o("PUT /put.txt HTTP/1.0\nContent-Length: 4\n$auth_header\nabcd",
		"HTTP/1.1 200 OK", 'PUT file, status 200');
	fail("PUT content mismatch")
		unless read_file("$root/put.txt") eq 'abcd';
	o("PUT /put.txt HTTP/1.0\n$auth_header\nabcd",
		"HTTP/1.1 411 Length Required", 'PUT 411 error');
	o("PUT /put.txt HTTP/1.0\nExpect: blah\nContent-Length: 1\n".
		"$auth_header\nabcd",
		"HTTP/1.1 417 Expectation Failed", 'PUT 417 error');
	o("PUT /put.txt HTTP/1.0\nExpect: 100-continue\nContent-Length: 4\n".
		"$auth_header\nabcd",
		"HTTP/1.1 100 Continue.+HTTP/1.1 200", 'PUT 100-Continue');

	# Check that CGI's current directory is set to script's directory
	system("cp $root/env.cgi $test_dir");
	o("GET /$test_dir_uri/env.cgi HTTP/1.0\n\n",
		"CURRENT_DIR=.*$test_dir", "CGI chdir()");
	o("GET /hello.shtml HTTP/1.0\n\n",
		'inc_begin.+root.+inc_end', 'SSI (include)');
	o("GET /hello.shtml HTTP/1.0\n\n",
		'exec_begin.+Makefile.+exec_end', 'SSI (exec)');

	# Manipulate the passwords file
	my $path = 'test_htpasswd';
	unlink $path;
	system("$exe -A $path a b c") == 0
		or fail("Cannot add user in a passwd file");
	system("$exe -A $path a b c2") == 0
		or fail("Cannot edit user in a passwd file");
	my $content = '';
	open FD, $path or fail("Cannot open passwd file: $!"); 
	$content .= $_ while (<FD>);
	close FD;
	$content =~ /^b:a:\w+$/gs or fail("Bad content of the passwd file");
	unlink $path;

	kill_spawned_child();
	do_embedded_test();
}

sub do_embedded_test {
	my $cmd = "cc -o $embed_exe $root/embed.c mongoose.c -I. ".
			"-DNO_SSL -lpthread -DPORT=\\\"$port\\\"";
	print $cmd, "\n";
	system($cmd) == 0 or fail("Cannot compile embedded unit test");

	spawn("./$embed_exe");
	o("GET /test_get_header HTTP/1.0\nHost: blah\n\n",
			'Value: \[blah\]', 'mg_get_header', 0);
	o("GET /test_get_var?a=b&my_var=foo&c=d HTTP/1.0\n\n",
			'Value: \[foo\]', 'mg_get_var 1', 0);
	o("GET /test_get_var?my_var=foo&c=d HTTP/1.0\n\n",
			'Value: \[foo\]', 'mg_get_var 2', 0);
	o("GET /test_get_var?a=b&my_var=foo HTTP/1.0\n\n",
			'Value: \[foo\]', 'mg_get_var 3', 0);
	o("POST /test_get_var HTTP/1.0\nContent-Length: 10\n\n".
		"my_var=foo", 'Value: \[foo\]', 'mg_get_var 4', 0);
	o("POST /test_get_var HTTP/1.0\nContent-Length: 18\n\n".
		"a=b&my_var=foo&c=d", 'Value: \[foo\]', 'mg_get_var 5', 0);
	o("POST /test_get_var HTTP/1.0\nContent-Length: 14\n\n".
		"a=b&my_var=foo", 'Value: \[foo\]', 'mg_get_var 6', 0);
	o("POST /test_get_request_info?xx=yy HTTP/1.0\nFoo: bar\n".
		"Content-Length: 3\n\na=b",
		'Method: \[POST\].URI: \[/test_get_request_info\].'.
		'HTTP version: \[1/0\].HTTP header \[Foo\]: \[bar\].'.
		'HTTP header \[Content-Length\]: \[3\].'.
		'Query string: \[xx=yy\].POST data: \[a=b\].'.
		'Remote IP: \[\d+\].Remote port: \[\d+\].'.
		'Remote user: \[\]'
		, 'request_info', 0);

	kill_spawned_child();
}

print "Congratulations. Test passed.\n";
