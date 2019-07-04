/********************************************************************
 * Author:  Carlos Moreno
 * Created: 2019-06
 *
 * Description:
 *
 *      This is a sample code to connect to a server through TCP.
 *      You are allowed to use this as a sample / starting point
 *      for the assignment (both problems require a program that
 *      connects to something).
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

enum Types {Correct, WrongStart, WrongEnd, WrongLength, WrongHash, TimeTooLong, TimeTooShort};

int socket_to_server (const char * IP, int port);
void process_connection (int server_socket, Types execution_type);
string urandom(int size);

int main(int argc, char * args[])
{
    string host = "127.0.0.1";
    int port = 10333;
    Types execution_type = Correct;
    
    if (argc == 2) {
        host = args[1];
    } else if (argc == 3) {
        host = args[1];
        port = atoi(args[2]);
    } else if (argc == 4) {
        host = args[1];
        port = atoi(args[2]);
        
        if (strcmp(args[3], "WrongStart") == 0)
            execution_type = WrongStart;
        else if (strcmp(args[3], "WrongEnd") == 0)
            execution_type = WrongEnd;
        else if (strcmp(args[3], "WrongLength") == 0)
            execution_type = WrongLength;
        else if (strcmp(args[3], "WrongHash") == 0)
            execution_type = WrongHash;
        else if (strcmp(args[3], "TimeTooLong") == 0)
            execution_type = TimeTooLong;
        else if (strcmp(args[3], "TimeTooShort") == 0)
            execution_type = TimeTooShort;
    }

    
    // The function expects an IP address, and not a
    // hostname such as "localhost" or ecelinux1, etc.
    int server_socket = socket_to_server (host.c_str(), port);
    
    if (server_socket != -1)
    {
        process_connection(server_socket, execution_type);
    }
    else
    {
        cout << "Connection not successful" << endl;
    }
    
    return 0;
}

int socket_to_server (const char * IP, int port)
{
    struct sockaddr_in address;
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr (IP);
    address.sin_port = htons(port);
    
    int sock = socket (AF_INET, SOCK_STREAM, 0);
    
    if (connect (sock, (struct sockaddr *) &address, sizeof(address)) == -1)
    {
        return -1;
    }
    
    return sock;
}

void process_connection (int server_socket, Types execution_type)
{
    try
    {
        // Receive challenge from server
        const string & challenge = read_packet (server_socket);
        
        // Create stream for challenge string for processing
        stringstream challenge_stream(challenge);
        
        // Retrieve hex encoded R
        string hex_R;
        getline(challenge_stream, hex_R, ',');
        
        // Retrieve hex encoded P
        string hex_P;
        getline(challenge_stream, hex_P, ',');
        
        // Change P if WrongStart
        if (execution_type == WrongHash)
            hex_P = string_to_hex(urandom(hex_P.size()*4));
        
        // Convert hex encoded R to string
        string R = hex_to_string(hex_R);
        string wrong_R = urandom(128);
        
        cout << "R: " << hex_R << endl;
        cout << "P: " << hex_P << endl;
        
        string solution;
        string hash_solution;
        
        // Send to server right not if TimeTooShort
        if (execution_type == TimeTooShort) {
            send (server_socket, "dummy\n", 7, MSG_NOSIGNAL);
            string result = read_packet(server_socket);
            close(server_socket);
        }
        
        // Calculate maximum and minimum processing time
        double max_duration = max_processing_time(hex_P.size()*4);
        double min_duration = min_processing_time(hex_P.size()*4);
        
        cout << "Minimum duration: " << min_duration << "s" << endl;
        cout << "Maximum duration: " << max_duration << "s" << endl;
        
        // Start timer
        time_t start;
        time(&start);
        
        // Proof of work
        do {
            if (execution_type == WrongStart)
                solution = wrong_R + urandom(128) + R;
            else if (execution_type == WrongEnd)
                solution = R + urandom(128) + wrong_R;
            else if (execution_type == WrongLength)
                solution = R + urandom(64) + R;
            else
                solution = R + urandom(128) + R;
            hash_solution = sha256(solution);
            
            // cout << "Hash: " << hash_solution << ", P hex: " << hex_P << endl;
            
            // Check maximum duration
            double duration = ( clock() - start ) / (double) CLOCKS_PER_SEC;
            if (duration > max_duration) {
                cerr << "Taking too long to process" << endl;
                close(server_socket);
                return;
            }
        } while (hash_solution.rfind(hex_P, 0) != 0);
        
        // Stop timer
        time_t end;
        time(&end);
        double duration = difftime(end, start);
        
        // Check minimum duration
        while (duration < min_duration) {
            usleep(0.5 * 1000 * 1000); // sleep for 0.5s
            duration += 0.5;
        }
        
        // Hex encode solution
        string hex_solution = string_to_hex(solution);
        hex_solution += '\n';
        
        // Sleep for 60s if TimeTooLong
        if (execution_type == TimeTooLong)
            usleep(60 * 1000 * 1000);
        
        // Send challenge solution to server
        cout << "Sending solution: " << hex_solution << endl;
        send (server_socket, hex_solution.c_str(), strlen(hex_solution.c_str()), MSG_NOSIGNAL);
        
        // Read result from server
        string result = read_packet(server_socket);
        cerr << "Result: " << result << endl;
        
        close (server_socket);
    }
    catch (connection_closed)
    {
    }
    catch (socket_error)
    {
        cerr << "Socket error" << endl;
    }
}
