# ICMP-traceroute

## Description
Written for Computer Networks course  

- finds route to target using ICMP echo requests of increasing TTL.
- uses raw Unix sockets (needs sudo access)
- not using active-wait but select()
- syscalls return values are checked for unforseen errors
- detects packets coming from incorrect hosts
- in some edge cases doesn't work according to the standard

task description (in Polish) in file `p1.pdf`

## Usage
`make` -> build the project and create the executable  
`./traceroute <ip address>`
