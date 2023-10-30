# SSH-Protocol-and-MITM-Attack

This project has two main parts. In the first part, I developed a client-server system that provides
secure file transfer. I implemented the SSH protocol to construct a secure channel between the
client and server and performed secure file transfer. I used the OpenSSL library to
implement the SSH protocol. The SSH protocol produces a symmetric key shared between the client
and server, and I used the OpenSSL library once again to use that key to transfer the file. 

In the second part, I developed a man-in-the-middle (MITM) attack against the SSH protocol that
I implemented in part 1. I created a MITM that pretends to be the target server, but instead
opens a secure connection to the client that it can use to read client communications forwarded to the
target server.
