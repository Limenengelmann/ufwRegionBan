local ipu = dofile "./iputils.lua"          -- IP utils

local function testFilter(filters)
    local testlog = {
    "Jan 19 00:51:53 hostname sshd[1057]: Disconnecting authenticating user username 67.235.197.136 port 45174: Too many authentication failures [preauth]",
    "Jan 17 06:15:29 hostname sshd[24818]: Disconnected from invalid user username2 119.193.33.206 port 62288 [preauth]",
    "Jan 17 19:24:16 hostname sshd[27453]: Disconnected from authenticating user username 212.64.78.28 port 57804 [preauth]"
    }
    local counter = 0;
    local ip;

    for _, l in ipairs(testlog) do
        for _, fltr in ipairs(filters) do
            ip = ip or l:match(fltr);
        end
        if ip then
            print("Matched:", ip);
            counter = counter +1;
        end
        ip = nil;
    end
    print("Filtertest: Matched ", counter.."/"..#testlog, "ips");
    return counter == #testlog;
end

local function testIPutils()
    local ip1 = "192.168.10.200"
    local ip2 = "192.168.11.120"

    print(ip1)
    print(ipu.ip2int(ip1))
    print(ipu.int2ip(ipu.ip2int(ip1)))

    -- test:
    for _, l in ipairs(ipu.iprange2cidr(ip1, ip2)) do
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

return {
    testFilter = testFilter,
    testIPutils = testIPutils
}
