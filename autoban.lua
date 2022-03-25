-- read logfile parse out the ip addresses
-- query the net ranges and automatically create a country profile

local testing = dofile "./tests.lua"   -- load testing functions

-- ip helpers
local function ip2int (s)
    -- transform ip string to an integer representation
    local d1, d2, d3, d4 = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)");
    d1 = math.tointeger(d1);
    d2 = math.tointeger(d2);
    d3 = math.tointeger(d3);
    d4 = math.tointeger(d4);
    return (d1<<(3*8)) + (d2<<(2*8)) + (d3<<(1*8)) + d4;
end

local function int2ip (n)
    local s = "";
    s = "."..n % 256 .. s    -- 2^8
    n = n >> 8;
    s = "."..n % 256 .. s    -- 2^8
    n = n >> 8;
    s = "."..n % 256 .. s    -- 2^8
    n = n >> 8;
    s = n % 256 .. s         -- skip dot
    return s;
end

local function iMask(s)
    return math.tointeger((2^32 - 2^(32-s)))
end

local function iprange2cidr(ipstart, ipend)
    local startR = ip2int(ipstart)
    local endR = ip2int(ipend)

    local result = {}

    while endR >= startR do
        maxSize = 32
        while maxSize > 0 do
            mask = (iMask(maxSize - 1))
            maskBase = startR & mask
            if maskBase ~= startR then
                break
            end
            maxSize = maxSize - 1
        end
        x = math.log(endR - startR + 1)/math.log(2)
        maxDiff = math.floor(32 - math.floor(x))

        if maxSize < maxDiff then
            maxSize = maxDiff
        end

        ip = int2ip(startR)
        cidr = ip..'/'..maxSize
        result[#result + 1] = cidr
        startR = startR + math.tointeger(2^(32-maxSize))
    end
    return result
end

-- whois helpers
local function whois2disk(iptable, update, test)
    local update = update or false;
    local test = test or false;
    -- lookup ips in iptable with "whois" and write the entries to file
    local f;
    local whostring;
    local exists;
    local counter = 0;

    for _, ip in ipairs(iptable) do
        exists = io.open("whois/"..ip, "r");
        if not exists then
            print("Adding "..ip)
            iptable[ip] = true;     -- new values
            counter = counter + 1;
        end
        if not exists or (exists and update) then
            f = io.popen("whois "..ip);
            whostring = f:read("a");
            f:close();
            if not test then 
                f = io.open("whois/"..ip, "w");
                f:write(whostring);
                f:close();
            end
        end
        exists = exists and exists:close();  -- only close valid streams
    end
    print("Added ".. counter .." new addresses\n");
    return true;
end

local function readwhois(iptable)
    -- read files in the directory whois/* and return a table with their inhalte
    local whotable = {};
    local f;
    for _, ip in ipairs(iptable) do
        f = io.open("whois/"..ip);
        if f then
            whotable[ip] = f:read("a");
        end
    end
    return whotable;
end

-- inetnum
-- netrange
local function getIPrange(whoisentry)
    local nr = whoisentry:match("[Nn]et[Rr]ange%s*:(.-)\n");
    local inum = whoisentry:match("inetnum%s*:(.-)\n");
    --print("nr:", nr,"inum", inum);
    local res1 = nr or inum;
    local res2;
    res1, res2 = res1:match("%s*([%d%.%/]+)%s*%-?%s*([%d%.]*)%s*");
    --print("res1:", res1, "res2:", res2);
    local range;
    if res1:find("/") then
        range = false;
    elseif res2 ~= "" then
        range = true;
    end
    return range, res1, res2;
end

-- log helpers
local function parselog(logpath, filters)
    -- extract ip addresses from the log that match the hardcoded criterium
    local filters = {"(%d+%.%d+%.%d+%.%d+).+:11:.*%[preauth%]",
                     "(%d+%.%d+%.%d+%.%d+).+: Too many authentication failures %[preauth%]",
                    };
    local f = assert(io.open(logpath, "r"));
    local iptable = {};
    local ip;
    for l in f:lines() do
        for _, fltr in ipairs(filters) do
            ip = ip or l:match(fltr);
        end
        if ip then
            iptable[#iptable + 1] = ip;
        end
    end
    f:close();
    if #iptable > 1 then
        table.sort(iptable, function (s1, s2) return ip2int(s1) < ip2int(s2) end);
    end
    return iptable;
end

-- country helpers
local function getCountry(whoisentry)
    return whoisentry:match("[cC]ountry%s*:%s*(%w+)%s*");
end

local countries = dofile("countries.lua");  -- a2, a3, region lookup tables

-- get bantable
local function getBantable(whotable, iptable)
    -- whotable for whoisentries, iptable to check if the ip is new
    local bantable = {};

    for ip, w in pairs(whotable) do
        local cntr = getCountry(w);
        if cntr and countries.a2[cntr] then
            local reg = countries.a2[cntr].region;
            local range, i1, i2 = getIPrange(w);
            if range ~= nil then
                local ips;  -- get table with subdomains in CIDR notation
                if range then
                    ips = iprange2cidr(i1, i2);
                else
                    ips = {i1};
                end
                --print(ip, cntr, reg, range, i1 ," - ", i2, #ips);
                bantable[ip] = {["country"]=cntr, ["region"]=reg, ["range"]=range, ["ips"]=ips, ["new"]=iptable[ip]};
            end
        end
    end
    return bantable;
end

-- ufw helpers
local function banUFW(bantable, banloc)
    --syntax:    sudo ufw prepend deny from 120.92.0.0/17
    local cmd_base = "sudo ufw prepend deny from ";
    
    local failed = {};
    -- counters --
    local c = {}
    c.skip = 0;
    c.add = 0;
    c.fail = 0;

    for ip, bt in pairs(bantable) do
        if not bt.new then c.skip = c.skip + 1; goto continue; end
        --print(ip, bt.country, banloc.country[bt.country], bt.region, banloc.region[bt.region])
        if banloc.country[bt.country] or banloc.region[bt.region] then   --check country first, then region
            for _, r in ipairs(bt.ips) do
                local cmd = cmd_base .. r;
                --print(cmd);
                local ret, exit, excode = os.execute(cmd);
                if ret then
                    c.add = c.add + 1;
                else
                    c.fail = c.fail + 1;
                    failed[#failed+1] = cmd;
                end
            end
        end
        ::continue::
    end
    print("Added: ", c.add, ", skipped: ", c.skip, ", failed: ", c.fail);
    if #failed > 0 then
        print("Failed commands: ");
        for i, cmd in ipairs(failed) do
            print(cmd);
        end
        print("\n");
    end
end

-- ufw status stats
local function showStats(bantable, banloc)
    country_stats = {};
    region_stats = {};
    --banned countries and regions--
    bcountry_stats = {};    
    bregion_stats = {};

    for ip, bt in pairs(bantable) do
        local val = country_stats[bt.country];
        country_stats[bt.country] = val and val + 1 or 1;
        val = region_stats[bt.region];
        region_stats[bt.region] = val and val + 1 or 1;
        if banloc.country[bt.country] or banloc.region[bt.region] then   --TODO create final bantable to pass to ufwBan so this doesnt get repeated
            local val = bcountry_stats[bt.country];
            bcountry_stats[bt.country] = val and val + 1 or 1;
            local val = bregion_stats[bt.region];
            bregion_stats[bt.region] = val and val + 1 or 1;
        end
    end
    print("-- Stats --\n");
    print("-- Countries: --");
    for attr, val in pairs(country_stats) do
        print(attr, val);
    end
    print("\n-- Regions --");
    for attr, val in pairs(region_stats) do
        print(attr, val);
    end
    print("\n-- Banned Countries --");
    for attr, val in pairs(bcountry_stats) do
        print(attr, val);
    end
    print("\n-- Banned Regions --");
    for attr, val in pairs(bregion_stats) do
        print(attr, val);
    end
end

-- TODO create final bantable before passing to ufwBan, so stats can be printed easier about it
-- TODO move to ranges and away from single ips (prob saves storage in future)
-- TODO write function to automatically remove old deny rules when updating whois etc.
------------------------------------------------------------

-- Tables: 
-- iptables: list of filtered ips (key 0,1,...) and if its newly found (key <ip> : true/false)
-- whotable: dict with saved whois entries (as strings) (key <ip> : <whois-entry>
-- bantable: dict with country informations found ip-ranges, and equiv. CIDR notation ranges (key <ip>: attr: country, region, range, ips)
-- banloc  : dict with banned regions/countries as truthtable (key <region|a2-code>: true/nil)

local logfile = "/var/log/auth.log";    -- default location on ubuntu I guess?
local update = false;
local test = true;

-- Filters --
-- needs to capture ip address!
-- TODO fix filters
local filters = {"(%d+%.%d+%.%d+%.%d+).+:11:.*%[preauth%]",
                 "(%d+%.%d+%.%d+%.%d+).+: Too many authentication failures %[preauth%]",
                };

-- Countries 2 Ban --
local banloc = {region={}; country={}};
banloc.region["RIPE NCC"]  = nil    -- europe/middle east/russia
banloc.region["ARIN"]      = true   -- north america
banloc.region["APNIC"]     = true   -- asia/india/australia
banloc.region["LACNIC"]    = true   -- latin america
banloc.region["AFRINIC"]   = true   -- africa

-- banned automatically --
banloc.country["RU"] = true         -- russia
--banloc.country["CN"] = true       -- china
--banloc.country["US"] = true       -- usa

-- ban commands
-- TODO if filter changes, everything needs to be processed again
if test then
    -- TODO verbosity levels
    testing.testFilter(filters);
else
    if(arg[1]) then
        logfile = arg[1];
    end
    local iptable = parselog(logfile);
    whois2disk(iptable, update, test);
    local whotable = readwhois(iptable);
    local bantable = getBantable(whotable, iptable);
    banUFW(bantable, banloc);
    showStats(bantable, banloc);
end
