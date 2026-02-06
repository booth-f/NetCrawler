# NetCrawler - V1.0 

NetCrawler is an open source enterprise network mapping program.

The primary use of this tool is to log into 1 switch and utilizing the information from CDP/LLDP neighbors discover other switches on the network and attempt to log into them using the specified credentials in the environment variables.

## Syntax
---
In order to use NetCrawler to crawl a network you need to first specify 2 environment variables, and a third optional one if you need it.

### Environment Variables
---

NC_USER - The username you want the program to use when logging in via ssh

NC_PASS - The password

#### Optional 
---

NC_DISABLE_SITE_CHECK  - Enable or disable the automatic site check. By default NetCrawler will use the first thing in the system hostname to determine if a device is part of the same "site" for example:

HS-RM202-SW1

HS-RM302-SW1

ES-RM302-SW1


without disable site check being set to "1" it will return a network topology with whatever prefix the first switch it connects to has, so if we start at HS-RM202-SW1 our network topology will only contain switches with the HS-* prefix in our final output.


### Command Examples:
---

When running the program on MacOS or Linux you can use the following commands:

export NC_USER=admin

export NC_PASS=P@ssw0rd!

export NC_DISABLE_SITE_CHECK=1

./Netcrawler 10.0.0.1 

The program does not display any output or indication that it's working. After a few minutes it will return output to the screen like:

manageable switches discovered: 9


and the program will drop a topologies.png image file in the directory where it was run from. 


### NOTES

THIS PROGRAM IS NOT FEATURE COMPLETE. While the program works well enough for use on Cisco-specific networks, it is not ready to handle networks that have multiple vendors. 

### Pull Requests
If you wish to help build upon or improve this program please feel free to submit a pull request and I'll make time to review it. 

If this program helps you at all, please consider adding a star to let me know!
