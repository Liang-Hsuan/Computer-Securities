/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2019-06
 *
 * Description:
 *
 *      You may use this file as a sample / starting point for the
 *      server in both questions.  In particular, you are allowed
 *      to submit your code containing verbatim fragments from this
 *      file.
 *
 *      For the most part, although the file is a .c++ file, the
 *      code is also valid C code  (with some exceptions --- pun
 *      intended! :-) )
 *
 * Copyright and permissions:
 *      This file is for the exclusive purpose of our ECE-458
 *      assignment 1, and you are not allowed to use it for any
 *      other purpose.
 *
 ********************************************************************/

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>

using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>

#include "common.h"

void listen_connections (int port);
void process_connection (int client_socket);
string urandom(int size);

int P_length = 8;

int main (int argc, char * argv[])
{
    int port = 10333;
    
    if (argc == 2)
        port = atoi(argv[1]);
    else if (argc == 3) {
        port = atoi(argv[1]);
        //P_length = atoi(argv[2]);
    }
    
    listen_connections (port);
    
    return 0;
}

void listen_connections (int port)
{
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_len;
    
    server_socket = socket (AF_INET, SOCK_STREAM, 0);
    
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons (port);
    
    if (bind (server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) == -1)
    {
        cout << "Could not bind socket to address:port" << endl;
        throw socket_error();
    }
    
    listen (server_socket, 5);
    
    while (true)
    {
        client_len = sizeof(client_address);
        client_socket = accept (server_socket,
                                (struct sockaddr *) &client_address,
                                &client_len);
        
        pid_t pid = fork();
        
        // if we're the child process
        if (pid == 0)
        {
            // only the parent listens for new connections
            close (server_socket);
            
            // detach grandchild process -- parent returns immediately
            if (fork() == 0)
            {
                // Allow the parent to finish, so that the grandparent
                // can continue listening for connections ASAP
                usleep (10000);
                
                process_connection (client_socket);
            }
            
            return;
        }
        // parent process; close the socket and continue
        else if (pid > 0)
        {
            int status = 0;
            waitpid (pid, &status, 0);
            close (client_socket);
        }
        else
        {
            cerr << "ERROR on fork()" << endl;
            return;
        }
    }
}

void process_connection (int client_socket)
{
    try
    {
        // Generate R
        string R = urandom(128);
        string hex_R = string_to_hex(R);
        
        // Generate P
        cout << "P length: " << P_length << endl;
        string P = urandom(P_length);
        string hex_P = string_to_hex(P);
        
        cout << "R: " << hex_R << ", P: " << hex_P << endl;
        
        // Concate R and P
        string challenge = hex_R + ',' + hex_P + '\n';
        
        // Set 30 seconds timeout
        // http://forums.codeguru.com/showthread.php?353217-example-of-SO_RCVTIMEO-using-setsockopt()&p=1213892#post1213892
        struct timeval tv;
        tv.tv_sec = max_processing_time(P_length) + 0.1; // plus 0.1 account for transmission delay
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
        
        // Start timer
        time_t start;
        time(&start);
        
        // Send challenge to client
        cout << "Sending challenge: " << challenge << endl;
        send(client_socket, challenge.c_str(), strlen(challenge.c_str()), MSG_NOSIGNAL);
        
        // Receive solution from client
        const string & hex_solution = read_packet(client_socket);
        
        // Stop timer
        time_t end;
        time (&end);
        double duration = difftime(end, start);
        
        cout << "Taking " << setprecision(2) << duration << "s to receive from client" << endl;
        
        // Calculate minimum processing time
        int min_duration = min_processing_time(P_length);
        
        cout << "Minimum duration: " << setprecision(2) << min_duration << "s" << endl;
        
        // Check client processing time
        if (duration < min_duration) { // plus 0.1 account for transmission delay
            cerr << "Time for processing taking too short" << endl;
            close(client_socket);
            return;
        }
        
        // Check solution is 768-bit hex encoded (i.e. 384-bit string)
        if (hex_solution.length() != 96) {
            cerr << "Solution length is not 384 bit" << endl;
            close(client_socket);
            return;
        }
        
        cout << "Received solution: " << hex_solution << endl;
        
        // Decode hex solution
        string solution = hex_to_string(hex_solution);
        
        // Check solution starts with R
        if (solution.rfind(R, 0) != 0) {
            cerr << "Solution not start with R" << endl;
            close(client_socket);
            return;
        }
        
        // Check solution ends with R
        // https://stackoverflow.com/a/874160
        if (solution.length() >= R.length()) {
            if (solution.compare(solution.length() - R.length(), R.length(), R) != 0) {
                cerr << "Solution not end with R" << endl;
                close(client_socket);
                return;
            }
        } else {
            cerr << "Solution not end with R" << endl;
            close(client_socket);
            return;
        }
        
        // Check SHA256 solution starts with P
        if (sha256(solution).rfind(hex_P, 0) != 0) {
            cerr << "Hashed solution not start with P" << endl;
            close(client_socket);
            return;
        }
        
        cout << "Solution ok!" << endl;
        
        // Send welcome to client
        send(client_socket, "welcome\n", 9, MSG_NOSIGNAL);
        
        close(client_socket);
    }
    catch (connection_closed)
    {
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
}
