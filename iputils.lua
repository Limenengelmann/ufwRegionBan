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

local function test()
    local ip1 = "192.168.10.200"
    local ip2 = "192.168.11.120"

    print(ip1)
    print(ip2int(ip1))
    print(int2ip(ip2int(ip1)))

    -- test:
    for _, l in ipairs(iprange2cidr(ip1, ip2)) do
        print(l);
    end

    print("-- expected result:")
    print("192.168.10.200/29")
    print("192.168.10.208/28")
    print("192.168.10.224/27")
    print("192.168.11.0/26")
    print("192.168.11.64/27")
    print("192.168.11.96/28")
    print("192.168.11.112/29")
end
