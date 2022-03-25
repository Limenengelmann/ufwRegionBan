# ufwRegionBan
Parses sshd logs with a given filter and adds ufw rules to deny requests from the found IPs.
Decision to block is based on the region/country of the IP, which is determined from its whois record.
If an IP is found, it blocks the whole address block it belongs to, if that belongs to a banned region/country specified in config.lua.
Maybe useful if you have a private server and just want to nuke some ssh bots from the other side of the world.
