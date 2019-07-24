# Problem 1:

## Files
 `client_skelenton.cpp`, `server_skelenton.cpp` , `common.h`.

## Compile

``` Shell
make server
make client

# alternatively
make default
```

## Run

``` Shell
# port (optional) P_length (optional)
./server.out 10333 16

# host port execution_type (optional)
./client.out 127.0.0.1 10333 Correct
```

# Implementation

**server_skelenton.cpp**:

Built on top of the server file from Learn. Follow all the steps from the assignment manual:

1. Connect with client.
2. Generate random 128-bit R and configurable random 8-bit multiple length P.
3. Send hex encoded R and P to client for challenge.
4. Receive hex encoded solution from client.
5. Check the solution is correct.
6. If correct response "welcome" to client.
7. Close connection.

Error checking:

1. Client taking too short to process.
2. Client taking too long to process.
3. Solution is not 384-bit long.
4. Solution string not start with R.
5. Solution string not end with R.
6. SHA256 solution not start with P.

References:

- Set socket timtout: http://forums.codeguru.com/showthread.php?353217-example-of-SO_RCVTIMEO-using-setsockopt()&p=1213892#post1213892
- Check string end with: https://stackoverflow.com/a/874160

**client_skelenton.cpp**:

Built on top of the client file from Learn. Follow all the steps from the assignment manual:

1. Connect with server.
2. Receive hex encoded challenge R and P.
3. Proof of work with given R and P.
4. Abort if taking too long to process. Wait if taking too short to process.
5. Send solution to the server.
6. Get result response back from server.
7. Close connection.

Testing:

1. Solution not start with R.
2. Solution not end with R.
3. Solution is not 384-bit long.
4. Solution hash not start with P.
5. Time taking too long.
6. Time taking too short.

**common.h**:

Define some common functions used both in server and client.

References:

- String hex conversion: https://stackoverflow.com/a/3382894
- urandom: https://stackoverflow.com/a/35727057
- SHA256: https://stackoverflow.com/a/2458382

# Problem 2

## Files

`time_attack.cpp`.

## Compile

``` Shell
make time_attack

# alternatively
make default
```

## Run

``` Shell
# user (optional)
./time_attack.out l63ma
```

# Implementation

**time_attack.cpp**:

Built on top of the client file from Learn. Follow all the steps from the assignment manual:

1. Connect with server.
2. Send user name.
3. Wait for a bit to ready to send password.
4. Test with current solution.
5. Iterate multiple times with each letter to record timing.
6. Calculate each letter's confidence interval.
7. If there is no apparent candidate letter, don't update current solution and go back to step 4.
8. If there is apparent candidate letter, update current solution then test the password with current solution.
9. If attempt solution is correct break the loop, else go back to step 4.

## References

- Confidence interval http://onlinestatbook.com/2/estimation/mean.html

# Acknowledgement

Collaberated with *Youdongchen Zhao* (`y396zhao`).
