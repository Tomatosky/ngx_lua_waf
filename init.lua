require 'config'

local ngxFind = ngx.re.find

function getClientIp()
    local headers = ngx.req.get_headers()
    return headers["X_FORWARDED_FOR"] or headers["X-REAL-IP"] or ngx.var.remote_addr or "0.0.0.0"
end

function utf8len(str)
    if not str or type(str) ~= "string" or #str <= 0 then
        return 0
    end
    local length = 0
    local i = 1
    while true do
        local curByte = string.byte(str, i)
        local byteCount = 1
        if curByte > 239 then
            byteCount = 4
        elseif curByte > 223 then
            byteCount = 3
        elseif curByte > 128 then
            byteCount = 2
        else
            byteCount = 1
        end
        i = i + byteCount
        length = length + 1
        if i > #str then
            break
        end
    end
    return length
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method, url)
    if attackLog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()

        line = realIp .. " [" .. time .. "] \"" .. method .. " " .. url .. "\" "
        if ua then
            line = line .. " \"" .. ua .. "\"\n"
        else
            line = line .. "\n"
        end

        local filename = logDir .. '/' .. servername .. "_sec.log"
        write(filename, line)
    end
end

function denyCC()
    if CCDeny then
        local ip = getClientIp()
        local servername = ngx.var.server_name
        local token = ip .. servername
        local limit = ngx.shared.limit
        local req, _ = limit:get(token)
        if req then
            if req == CCCount then
                limit:set(token, CCCount + 1, CCBlockTime)
                log('CC', '-')
                ngx.exit(CCCode)
                return true
            elseif req > CCCount then
                ngx.exit(CCCode)
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCDuration)
        end
    end
    return false
end

function uri()
    if uriCheck then
        local request_uri = ngx.var.request_uri
        if request_uri ~= nil then
            if ngxFind(request_uri, "[" .. checkRex .. "]", "jo") then
                log('illegal uri', request_uri)
                ngx.exit(uriCheckCode)
                return true
            end
        end

        local method = ngx.req.get_method()
        if method == "POST" then
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if not args then
                return
            end
            for key, val in pairs(args) do
                if ngxFind(val, "[" .. checkRex .. "]", "jo") then
                    log('illegal value', val)
                    ngx.exit(uriCheckCode)
                    return true
                end
            end
        end
    end
    return false
end