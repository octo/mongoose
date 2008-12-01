#!/usr/bin/env perl
# This script is used to test Mongoose web server
# $Id$

use IO::Socket;

my $port = 23456;
my $pid = undef;
my $num_requests;
my $dir = 'test_dir';
my $alias = "/aliased=/etc/,/ta=$dir";
my $config = '../mongoose.conf';
my $exe = '../mongoose';
my $exit_code = 0;

my @files_to_delete = ('debug.log', 'access.log', $config, 'put.txt',
	"$dir/index.html", "$dir/env.cgi", 'binary_file');

END {
	unlink @files_to_delete;
	rmdir $dir;
	kill(9, $pid) && waitpid($pid, 0) if defined($pid);
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
	my ($request, $do_not_log) = @_;
	my $sock = IO::Socket::INET->new(Proto=>"tcp",
		PeerAddr=>'127.0.0.1', PeerPort=>$port);
	fail("Cannot connect: $!") unless $sock;
	$sock->autoflush(1);
	print $sock $_ foreach (split //, $request);
	my ($out, $cl, $tl, $body) = ('', 0, 0, 0);
	while ($line = <$sock>) {
		$out .= $line;
		$cl = $1 if $line =~ /Content-Length: (\d+)/;
		$body++ if  $line =~ /^\s*$/;
		$tl += length($line) if $body;
		last if $cl and $tl >= $cl;
	};
	close $sock;
	$num_requests++ unless $do_not_log;
	my $num_logs = get_num_of_log_entries();

	unless ($num_requests == $num_logs) {
		#print read_file('access.log');
		fail("Request has not been logged: [$request]")
	}

	return $out;
}

# Send the request. Compare with the expected reply. Fail if no match
sub o {
	my ($request, $expected_reply, $message, $dont_log) = @_;
	my $reply = req($request, $dont_log);
	fail("$message ($reply)") unless $reply =~ /$expected_reply/s;
	print "PASS: $message\n";
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

####################################################### ENTRY POINT

unlink @files_to_delete;

# Make sure we export only symbols that start with "mg_", and keep local
# symbols static.
if ($^O =~ /darwin|bsd|linux/) {
	$out = `(cd .. && cc -c mongoose.c && nm mongoose.o) | grep ' T '`;
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
o("GET /hello.txt HTTP/1.0\n\n", 'HTTP/1.1 200 OK', 'Loading config file');
$port = $saved_port;
unlink $config;
kill(9, $pid) && waitpid($pid, 0) if defined($pid);

# Spawn the server on port $port
spawn("$exe -ports $port -access_log access.log -error_log debug.log ".
		"-aliases $alias -auth_PUT passfile");

# Try to overflow: Send very long request
req('POST ' . '/..' x 100 . 'ABCD' x 3000 . "\n\n", 1); # don't log this one

o("GET /hello.txt HTTP/1.0\n\n", 'HTTP/1.1 200 OK', 'GET regular file');
o("GET /%68%65%6c%6c%6f%2e%74%78%74 HTTP/1.0\n\n",
	'HTTP/1.1 200 OK', 'URL-decoding');

# Test HTTP version parsing
o("GET / HTTPX/1.0\r\n\r\n", '400 Bad Request', 'Bad HTTP Version', 1);
o("GET / HTTP/x.1\r\n\r\n", '400 Bad Request', 'Bad HTTP maj Version', 1);
o("GET / HTTP/1.1z\r\n\r\n", '400 Bad Request', 'Bad HTTP min Version', 1);
o("GET / HTTP/02.0\r\n\r\n", '505 HTTP version not supported',
	'HTTP Version >1.1');

mkdir $dir unless -d $dir;
o("GET /$dir/not_exist HTTP/1.0\n\n", 'HTTP/1.1 404', 'PATH_INFO loop problem');
o("GET /$dir HTTP/1.0\n\n", 'HTTP/1.1 301', 'Directory redirection');
o("GET /$dir/ HTTP/1.0\n\n", 'Modified', 'Directory listing');
open FD, ">$dir/index.html"; print FD "tralala"; close FD;
o("GET /$dir/ HTTP/1.0\n\n", 'tralala', 'Index substitution');
o("GET /ta/ HTTP/1.0\n\n", 'Modified', 'Aliases');
o("GET /not-exist HTTP/1.0\r\n\n", 'HTTP/1.1 404', 'Not existent file');

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
	open FD, ">$filename";
	close FD; 
	o("GET /$filename HTTP/1.0\n\n",
		"Content-Type: $mime_types->{$key}", ".$key mime type");
	unlink $filename;
}

# Get binary file and check the integrity
my $binary_file = 'binary_file';
my $f2 = ''; 
foreach (0..123456) { $f2 .= chr(int(rand() * 255)); }
open FD, ">$binary_file";
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
print "PASS: Range support\n";

unless ($ARGV[0] eq "basic_tests") {
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
	fail("PUT content mismatch") unless read_file('put.txt') eq '1234567';
	o("PUT /put.txt HTTP/1.0\nContent-Length: 4\n$auth_header\nabcd",
		"HTTP/1.1 200 OK", 'PUT file, status 200');
	fail("PUT content mismatch") unless read_file('put.txt') eq 'abcd';
	o("PUT /put.txt HTTP/1.0\n$auth_header\nabcd",
		"HTTP/1.1 411 Length Required", 'PUT 411 error');
	o("PUT /put.txt HTTP/1.0\nExpect: blah\n$auth_header\nabcd",
		"HTTP/1.1 417 Expectation Failed", 'PUT 417 error');

	# Check that CGI's current directory is set to script's directory
	system("cp env.cgi $dir");
	o("GET /$dir/env.cgi HTTP/1.0\n\n",
		"CURRENT_DIR=.*$dir", "CGI chdir()");
	o("GET /hello.shtml HTTP/1.0\n\n",
		'inc_begin.*root.*inc_end', 'SSI (include)');
	o("GET /hello.shtml HTTP/1.0\n\n",
		'exec_begin.*env.cgi.*exec_end', 'SSI (exec)');

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
}

# Embedded test
=begin
spawn("./example");
o("GET /?name1=776655 HTTP/1.0\n\n", '776655', 'Embedded GET wrong');
o("GET /not_exist HTTP/1.0\n\n", 'Oops.', 'Custom error handler wrong');
o("GET /huge HTTP/1.0\n\n", 'AAA', 'Huge data handler failed');
o("GET /users/joe/ HTTP/1.0\n\n", 'wildcard', 'Wildcard URI failed');
o("GET /secret HTTP/1.0\n\n", 'WWW-Auth', 'Page protection failed');
o("POST /post HTTP/1.0\nContent-Length: 7\n\n1234567", 'Written 7 bytes',
	'Embedded POST failed');
=cut


print "Congratulations. Test passed.\n";
