-- read logfile, parse out ip addresses after given filter
-- query country/region info about the IPs and add ufw rules depending on that 

local testing   = dofile "tests.lua"        -- load testing functions
local ipu       = dofile "iputils.lua"      -- IP utils
local wiu       = dofile "whoisutils.lua"   -- whois utils
local countries = dofile "countries.lua"    -- a2, a3, region lookup tables
local ufwu      = dofile "ufwutils.lua"     -- ufw
local cfg       = dofile "config.lua"       -- banned regions/countries

if test then
    -- TODO verbosity levels
    testing.testFilter(filters);
    testing.testIPutils();
end

local banlocs = cfg.banlocs
local filters = cfg.filters
local logfile = cfg.logfile
local update  = cfg.update
local test    = cfg.test

-- TODO help output
if(arg[1]) then
    logfile = arg[1];
end

if (test) then
    testing.testFilter(filters)
    testing.testIPutils()
    return
end

local iptable = ufwu.parseLog(logfile);
wiu.whois2disk(iptable, update);
local whotable = wiu.readwhois(iptable);
local bantable = ufwu.getBantable(whotable, iptable);
--ufwu.addUFWdeny(bantable, banlocs);
ufwu.showStats(bantable, banlocs);
