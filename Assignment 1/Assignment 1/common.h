#include <algorithm>
#include <stdexcept>

#include <openssl/sha.h>
#include <iomanip>

using namespace std;

class connection_closed {};
class socket_error {};

// Defined redundantly in client and server source files --- you may
// want to refactor it as a common function and use it for both.
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

static const char* const lut = "0123456789abcdef";

string string_to_hex(const string& input)
{
    size_t len = input.length();
    
    string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

string hex_to_string(const string& input)
{
    size_t len = input.length();
    if (len & 1) throw invalid_argument("odd length");
    
    string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw invalid_argument("not a hex digit");
        
        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw invalid_argument("not a hex digit");
        
        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

string urandom(int size) {
    int length = size/8;
    char * random_value = new char[length]; // Declare value to store data into
    ifstream urandomf("/dev/urandom", ios::in|ios::binary); // Open stream
    if(urandom) // Check if stream is open
    {
        urandomf.read(random_value, length); // Read from urandom
        if(urandomf) // Check if stream is ok, read succeeded
        {
            return random_value;
        }
        else // Read failed
        {
            std::cerr << "Failed to read from /dev/urandom" << endl;
        }
        urandomf.close(); //close stream
    }

    cerr << "Failed to open /dev/urandom" << endl;
    return 0;
}

string sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

double min_processing_time(int p_length) {
    int num = p_length/8;
    return 2^num;
}

double max_processing_time(int p_length) {
    return min_processing_time(p_length)*1.5;
}
