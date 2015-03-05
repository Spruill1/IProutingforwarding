Authors: David Spruil, Elder Yoshida

Our implementation is fairly standard.  We are using select and fd_set to manage having
several sockets open for communication concurrently.  Each node runs a single UDP
socket for exchanging information with the other nodes; the other file descriptor is
used for user input.

We implemented routing and forwarding fully and are capable of sending a message across
the network as expected.  We've tested with normal, long networks, and networks with
loops, as well as networks that have remote nodes.

to compile run: g++ -std=c++0x -o node node.c ipsum.c
