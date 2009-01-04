PROG=	mongoose
SRCS=	main.c mongoose.c
COPT=	-W -Wall -std=c99 -pedantic -Os -s -D_POSIX_SOURCE -D_BSD_SOURCE

# Possible flags: (in brackets are rough numbers for 'gcc -O2' on i386)
# -DHAVE_MD5		- use system md5 library (-2kb)
# -DNDEBUG		- strip off all debug code (-5kb)
# -D_DEBUG		- build debug version (very noisy) (+7kb)
# -DNO_CGI		- disable CGI support (-5kb)
# -DNO_SSL		- disable SSL functionality (-2kb)
# -DNO_AUTH		- disable authorization support (-4kb)
# -DCONFIG=\"file\"	- use `file' as the default config file
# -DNO_SSI		- disable SSI support (-4kb)

all:
	@echo "make (linux|bsd|windows|rtems)"

linux:
	$(CC) $(COPT) $(CFLAGS) $(SRCS) -ldl -lpthread -o $(PROG)

bsd:
	$(CC) $(COPT) $(CFLAGS) $(SRCS) -lpthread -o $(PROG)

rtems:
	$(CC) -c $(COPT) $(CFLAGS) mongoose.c compat_rtems.c
	$(AR) -r lib$(PROG).a *.o && ranlib lib$(PROG).a 

# To build on Windows, follow these steps:
# 1. Download and install Visual Studio Express 2008 to c:\msvc8
# 2. Download and install Windows SDK to c:\sdk
# 3. Go to c:\msvc8\vc\bin and start "VIsual Studio 2008 Command prompt"
#    (or Itanium/amd64 command promt to build x64 version)
# 4. In the command prompt, go to mongoose directory and do "nmake windows"

#WINDBG=	/Zi /DDEBUG /Od
WINDBG=	/DNDEBUG /Os
WINOPT=	/MT /TC $(WINDBG) /nologo /DNDEBUG /W4 \
	/D_CRT_SECURE_NO_WARNINGS /DHAVE_STRTOUI64
windows: winexe windll

windll:
	cl $(WINOPT) mongoose.c /link /incremental:no /DLL \
		/DEF:win32_installer\dll.def /out:$(PROG).dll ws2_32.lib

winexe:
	cl $(WINOPT) $(SRCS) /link /incremental:no \
		/out:$(PROG).exe ws2_32.lib advapi32.lib

# Build for Windows under MinGW
#MINGWDBG= -DDEBUG -O0
MINGWDBG= -DNDEBUG -Os
MINGWOPT= -W -Wall -mthreads -Wl,--subsystem,console -DHAVE_STDINT \
	  $(MINGWDBG) -DHAVE_STDINT

mingw: mingwexe mingwdll
mingwdll:
	gcc $(MINGWOPT) mongoose.c -lws2_32 \
		-shared -Wl,--out-implib=$(PROG).lib -o $(PROG).dll

mingwexe:
	gcc $(MINGWOPT) $(SRCS) -lws2_32 -ladvapi32 -o $(PROG).exe 

man:
	cat mongoose.1 | tbl | groff -man -Tascii | col -b > mongoose.1.txt
	cat mongoose.1 | tbl | groff -man -Tascii | less

test: test-server
test-server:
	perl test/test.pl

release: clean
	F=mongoose-`perl -lne '/define\s+MONGOOSE_VERSION\s+"(\S+)"/ and print $$1' mongoose.c`.tgz ; cd .. && tar --exclude \*.svn --exclude \*.swp --exclude \*.nfs\* --exclude win32_installer -czf x mongoose && mv x mongoose/$$F

clean:
	rm -rf *.o *.core $(PROG) *.obj $(PROG).1.txt *.dSYM *.tgz
