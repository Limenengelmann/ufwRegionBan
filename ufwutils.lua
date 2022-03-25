local testing = dofile "./tests.lua"        -- load testing functions
local ipu = dofile "./iputils.lua"          -- IP utils
local wiu = dofile "./whoisutils.lua"       -- whois utils
local countries = dofile "countries.lua"    -- a2, a3, region lookup tables
local cfg = dofile "config.lua"         -- banned regions/countries

-- TODO create final bantable before passing to ufwBan, so stats about it can be printed
-- TODO write function to automatically remove old deny rules when updating whois etc.
-- TODO If filter changes, everything needs to be processed again
------------------------------------------------------------

-- Tables --
-- iptable : list of filtered ips (key 0,1,...) and if its newly found (key <ip> : true/false)
-- whotable: dict with saved whois entries (as strings) (key <ip> : <whois-entry>
-- bantable: dict with country informations found ip-ranges, and equiv. CIDR notation ranges (key <ip>: attr: country, region, range, ips)
-- banlocs : dict with banned regions/countries as truthtable (key <region|a2-code>: true/nil)

-- log helpers
local function parseLog(logpath, filters)
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
        table.sort(iptable, function (s1, s2) return ipu.ip2int(s1) < ipu.ip2int(s2) end);
    end
    return iptable;
end

-- get bantable
local function getBantable(whotable, iptable)
    -- whotable for whoisentries, iptable to check if the ip is new
    local bantable = {};

    for ip, w in pairs(whotable) do
        local cntr = wiu.getCountry(w);
        if cntr and countries.a2[cntr] then
            local reg = countries.a2[cntr].region;
            local range, i1, i2 = wiu.getIPrange(w);
            if range ~= nil then
                local ips;  -- get table with subdomains in CIDR notation
                if range then
                    ips = ipu.iprange2cidr(i1, i2);
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
local function addUFWdeny(bantable, banlocs)
    --ufw syntax:    sudo ufw prepend deny from 120.92.0.0/17
    local cmd_base = "sudo ufw prepend deny from ";
    
    local failed = {};
    -- counters --
    local c = {}
    c.skip = 0;
    c.add = 0;
    c.fail = 0;

    for ip, bt in pairs(bantable) do
        if not bt.new then c.skip = c.skip + 1; goto continue; end -- lua 5.3 has no continue kw
        --print(ip, bt.country, banlocs.country[bt.country], bt.region, banlocs.region[bt.region])
        if banlocs.country[bt.country] or banlocs.region[bt.region] then   --check country first, then region
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
local function showStats(bantable, banlocs)
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
        if banlocs.country[bt.country] or banlocs.region[bt.region] then
            --TODO create final bantable to pass to ufwBan so this doesnt get repeated
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

return {
    parseLog = parseLog,
    getBantable = getBantable,
    addUFWdeny = addUFWdeny,
    showStats = showStats,
}
