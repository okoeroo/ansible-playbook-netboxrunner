-- Intercept to avoid NAT U-turn
local target_revproxy_koeroo_lan = {
                "koeroo.net.",
                "www.koeroo.net.",
                "oscar.koeroo.net.",
                "cloud.koeroo.net.",
                "nextcloud.koeroo.net.",
                "api.koeroo.net.",
                "heimdall.koeroo.net.",
                "celebritiesspotted.com.",
                "www.celebritiesspotted.com.",
                "kuma.koeroo.net.",
                "mattermost.koeroo.net.",
                "netbox.koeroo.net."
              }

local target_seaport_koeroo_lan = {
                "ouilookup.koeroo.lan.",
                "portainer.koeroo.lan.",
                "mosquitto.koeroo.lan."
              }

function preresolve(dq)
    if dq.qtype == pdns.A then
        -- Search string
        local search_string = dq.qname:toString()

        -- Check list to revproxy
        for i, v in ipairs(target_revproxy_koeroo_lan) do
            if v == search_string then
                -- Enable CNAME chain resolution
                dq.followupFunction="followCNAMERecords"

                pdnslog("preresolve: " .. dq.qname:toString(), pdns.loglevels.Info)
                dq:addAnswer(pdns.CNAME, "revproxy.koeroo.lan.")
                dq.rcode = pdns.NOERROR
                return true
            end
        end

        -- Check list to seaport
        for i, v in ipairs(target_seaport_koeroo_lan) do
            if v == search_string then
                -- Enable CNAME chain resolution
                dq.followupFunction="followCNAMERecords"

                pdnslog("preresolve: " .. dq.qname:toString(), pdns.loglevels.Info)
                dq:addAnswer(pdns.CNAME, "seaport.koeroo.lan.")
                dq.rcode = pdns.NOERROR
                return true
            end
        end


        if (dq.qname:toString() == "vpn.koeroo.net.") then
            -- Enable CNAME chain resolution
            dq.followupFunction="followCNAMERecords"

            pdnslog("preresolve: " .. dq.qname:toString(), pdns.loglevels.Info)
            dq:addAnswer(pdns.CNAME, "vpn.koeroo.lan.")
            dq.rcode = pdns.NOERROR
            return true
        elseif (dq.qname:toString() == "mail.koeroo.net.") then
            -- Enable CNAME chain resolution
            dq.followupFunction="followCNAMERecords"

            pdnslog("preresolve: " .. dq.qname:toString(), pdns.loglevels.Info)
            dq:addAnswer(pdns.CNAME, "mailcow.koeroo.lan.")
            dq.rcode = pdns.NOERROR
            return true
        elseif (dq.qname:toString() == "mail.cyberz.nl.") then
            -- Enable CNAME chain resolution
            dq.followupFunction="followCNAMERecords"

            pdnslog("preresolve: " .. dq.qname:toString(), pdns.loglevels.Info)
            dq:addAnswer(pdns.CNAME, "mailcow.koeroo.lan.")
            dq.rcode = pdns.NOERROR
            return true
        end
    end
    return false
end

