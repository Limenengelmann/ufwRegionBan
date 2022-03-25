local banlocs = {region={}; country={}};

banlocs.region["RIPE NCC"]  = nil    -- europe/middle east/russia
banlocs.region["ARIN"]      = true   -- north america
banlocs.region["APNIC"]     = true   -- asia/india/australia
banlocs.region["LACNIC"]    = true   -- latin america
banlocs.region["AFRINIC"]   = true   -- africa

-- banned automatically --
banlocs.country["RU"] = true         -- russia
--banlocs.country["CN"] = true       -- china
--banlocs.country["US"] = true       -- usa

-- Filters --
-- TODO switch to regex filters
-- needs to capture ip address!
-- filters to parse the system authentication log for ssh login attempts on ubuntu
local filters = {"(%d+%.%d+%.%d+%.%d+).+:11:.*%[preauth%]",
                 "(%d+%.%d+%.%d+%.%d+).+: Too many authentication failures %[preauth%]",
                };

local logfile = "/var/log/auth.log";    -- default location on ubuntu
local update = false;                   -- reread whois records
local test = false;                      -- run tests

return {
    banlocs = banlocs,
    filters = filters,
    logfile = logfile,
    update = update,
    test = test,
}
