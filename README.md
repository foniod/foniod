This repo now contains 2 BPF programs:

 * tcpsniff for listening on outbound TCP connections
 * execvesniff for listening on exec() calls

In addition, TCPSniff contains the necessary glue code to send the collected
data in a specific JSON envelope to a webhook.

For more information, look at the README.md files in the directories.
