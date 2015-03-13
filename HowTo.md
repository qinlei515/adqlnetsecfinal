# For Network Security folks #

If you're testing our "live" server, located on 10.0.0.2 on the virtual network, you'll want the Live server build.zip download - this includes the public keys that are in use on those servers.

You should be able to extract everything and run qlad\_client.jar from the command line (java -jar qlad\_client.jar, for those not Java inclined) without modifying settings. This will obviously only work from within the virtual network.

If you want to create local servers, grab the Test build.zip download - this includes an entire setup, including sample server keys and a set of Diffie-Hellman parameters. The DH parameter generator is not included, but the format of the file is straightforward: print DHParameterSpec.getP() on one line, then pring DHParameterSpec.getG() on a new line.

You'll need to modify config/servers.txt - point the IP addresses to wherever you're running your servers, and start both servers (qlad\_kserver.jar and qlad\_cserver.jar) before running the client. Don't change the ports, they are not configurable in the servers.

We recommend setting up the live installation on your virtual lab machines(s), and leaving that config/servers.txt alone, and keeping separate the test copy for working with your own servers.

No credentials are included with the test build, nor are there any initial credentials on the live server. You will be prompted for a user name when you start the client, choose a new one and say "n" when asked if you've used it before to create a new set of credentials.