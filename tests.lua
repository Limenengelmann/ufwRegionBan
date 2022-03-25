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

return {
    testFilter = testFilter
}
