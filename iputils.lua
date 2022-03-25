-- IP helpers --

local function ip2int (s)
    -- transform ip string to an integer representation
    local d1, d2, d3, d4 = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)");
    d1 = math.tointeger(d1);
    d2 = math.tointeger(d2);
    d3 = math.tointeger(d3);
    d4 = math.tointeger(d4);
    return (d1<<24) + (d2<<16) + (d3<<8) + d4;
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
    -- tranform a range of ip's to cidr notation so ufw understands it
    -- assumes that an equivalent cidr notation exists
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

return {
    ip2int = ip2int,
    int2ip = int2ip,
    iprange2cidr = iprange2cidr
}
