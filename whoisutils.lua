-- whois helpers --

-- TODO move to ranges and away from single ips (to save storage)
local function whois2disk(iptable, update)
    local update = update or false;
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
            f = io.open("whois/"..ip, "w");
            f:write(whostring);
            f:close();
        end
        -- TODO assignment needed ?
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

-- country helpers
local function getCountry(whoisentry)
    return whoisentry:match("[cC]ountry%s*:%s*(%w+)%s*");
end

return {
    readwhois = readwhois,
    whois2disk = whois2disk,
    getIPrange = getIPrange,
    getCountry = getCountry
}
