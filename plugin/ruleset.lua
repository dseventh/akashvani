local Redis = require "resty.redis"
local Object = require "classic.classic"
local ngx_re = require "ngx.re"

local Ruleset = Object:extend()


function Ruleset.connectRedis()
	local redis_host = "127.0.0.1"
	local redis_port = 6379
	local redis_password = nil


	local red = Redis:new()
	
	red:set_timeout(100) -- 100 ms
    
    local res, err = red:connect(redis_host, redis_port)

    if not res then
        ngx.ERR("Failed to connect Redis: ", err)
       	return nil
    end

    

    if redis_password then
    	local res, err = red:auth(redis_password)
    	if not res then
        	ngx.ERR("Failed to authenticate Redis: ", err)
        	return nil
        end
    end

    -- TODO [bsinha] Figure out why is this not working
    --local ok, err = red:set_keepalive(100000, 10) -- tcp status : TIME_WAIT
    --if not ok then
        --ngx.say("failed to set keepalive: ", err)
    --end

    return red
end



function Ruleset:new(name)
	self._name = name
end

function Ruleset:getBalancerInfo(balancer_name, key)
	local red = Ruleset.connectRedis()
	return red:hget(balancer_name, key)
end

function Ruleset:getRoutes(applicationname)
	local red = Ruleset.connectRedis()
	return red:smembers(applicationname)
end

function Ruleset:getRules(applicationname, route)
	local red = Ruleset.connectRedis()
	return red:smembers(applicationname .. ":" .. route)
end

function Ruleset:getRule(rulekey, attribute)
	local red = Ruleset.connectRedis()
	return red:hget(rulekey, attribute)
end

function Ruleset:getRuleApplicableStages(rulekey)
	local red = Ruleset.connectRedis()
	local applicable_stages = {}
	local rules = {}	

	local rule_access_check, flag1 = red:hget("stage:access_check", rulekey)
	local rule_header_check, flag2 = red:hget("stage:header_check", rulekey)
	local rule_content_check, flag3 = red:hget("stage:content_check", rulekey)

	if (rule_access_check ~= ngx.null) then
		applicable_stages["stage:access_check"] = rule_access_check
	end

	if (rule_header_check ~= ngx.null) then
		applicable_stages["stage:header_check"] = rule_header_check
	end

	if (rule_content_check ~= ngx.null) then
		applicable_stages["stage:content_check"] = rule_content_check
	end


	return applicable_stages
end


function Ruleset:loadFromBuffer(content, defense)
	local cjson = require "cjson"
    local routes = cjson.decode(content)
    local appname = (routes["appName"])
    self._name = appname

    local red = Ruleset.connectRedis()


    local rules = cjson.decode(defense)

    local rulegroup = rules["rulegroup"]

    local access_check_rules = rules["access_check"]
    local header_check_rules = rules["http_header_check"]
    local content_check_rules = rules["content_check"]


    for k,v in pairs(access_check_rules) do
    	local rule = v["rule"]
    	local regex = v["regex"]
    	red:hset("stage:access_check" , rule, regex)
    end

    for k,v in pairs(header_check_rules) do
    	local rule = v["rule"]
    	local regex = v["regex"]
    	local name = v["name"]
    	red:hset("stage:header_check" , rule, name.."$"..regex) -- using <sl> as delimiter
    end

    for k,v in pairs(content_check_rules) do
    	local rule = v["rule"]
    	local regex = v["regex"]
    	red:hset("stage:content_check" , rule, regex)
    end

    ---------------------------------------------
    -- We will call Chetan's routes as balancer:2
    ---------------------------------------------
    red:hset("balancer:2" , "application", appname)
    red:hset("balancer:2" , "host", "localhost")
    red:hset("balancer:2" , "port", "8081")

    --HSET balancer:2 application /usr/src/app/.sp/SP-hello-shiftleft-0.0.1.jar.bin
	--HSET balancer:2 host localhost
	--HSET balancer:2 port 8081

	vulnerabilities = routes["vulnerabilites"]
            
    for k , v in pairs(vulnerabilities) do
        route = (v["route"])
        title = (v["title"])
        description = (v["description"])
        --------------------------------------------------------
        -- Taking the first one (assuming it exists... Errrr..)
        --------------------------------------------------------
        owaspCat = v["owaspCategories"][1]
        --ngx.say("Cat :" .. owaspCat)

        -------------------------------
        -- Adding the Route information
        -------------------------------

        red:sadd("application:".. appname, route)
        red:sadd("application:".. appname .. ":" .. route, owaspCat..":"..title)
        red:hset(owaspCat..":"..title , "category", owaspCat)
        red:hset(owaspCat..":"..title , "title", title)
        red:hset(owaspCat..":"..title , "description", description)

    end


end


function Ruleset:get_endpoint()
	-- TODO [bsinha] Support Multiple applications. As of now hardcoded.
	local red = Ruleset.connectRedis()
	local res, flags = red:hgetall("balancer:2")
    
	if not res then
		return nil
	end
	
	return res
end


function Ruleset:get_upstreams(application)
	local red = Ruleset.connectRedis()

	local res, flags = red:smembers(application)
	if not res then
		return nil
	end
	
	return res
end

function Ruleset:contains_upstream(application, upstream)
	local red = Ruleset.connectRedis()

	local res, flags = red:sismember(application, upstream)
	if not res then
		return nil
	end
	
	return res
end


function Ruleset:extract_params(s)
	local ans = {}
	for k,v in s:gmatch('([^&=]+)=([^&=]*)&?' ) do
		v = v:gsub('+', ' ')
		v = v:gsub('%%(%x%x)', function(h) return string.char(tonumber(h, 16)) end)
		ans[ k ] = v
	end

	return ans
end


function Ruleset:load_rules(application, request_uri)
	local red = Ruleset.connectRedis()
	local res, flags = red:smembers(application .. ":" .. request_uri)

	for k,v in pairs(res) do
		local rule =v
		local rule_props, flags = red:hgetall("ruleset:" .. rule)

		-- TODO [bsinha]
	end
end

--------------------------------------------------
-- Below three functions needs to be reused as one.
--------------------------------------------------
function Ruleset:apply_header_filter(application, request_uri, headers)
	local red = Ruleset.connectRedis()
	-- Check all the rules that belong to this group
	local res, flags = red:smembers(application .. ":" .. request_uri)


	for k,v in pairs(res) do
		local rule_key =  v

		-- Now look for this rule in the stage:access_check
		-- This is a O(1) retrieval of the rules for a given rule group
		local rule, err = red:hget("stage:header_check", rule_key)
		if (rule ~= ngx.null) then
			-- We chose $ as deimited between name and regex
			local res, err = ngx_re.split(rule, "\\$")
			local name = res[1]:lower()
			local regex = res[2]
			for p,q in pairs(headers) do
				if (p == name) then
					local m = ngx.re.match(q, regex)
		        	if m then
		        		-----------------------------------------------------------------
		        		-- The first one found will be blocked and we will skip the rest
		        		-----------------------------------------------------------------
		        		return true, "Blocked : " .. rule_key
		        	end
				end
			end
		end
	end
	return false, "success"
end

function Ruleset:apply_body_filter(application, request_uri, body_data)
	-- Check all the rules that apply here for a given stage/group
	local red = Ruleset.connectRedis()
	
	local cjson = require "cjson"

	-- Check all the rules that belong to this group
	local res, flags = red:smembers(application .. ":" .. request_uri)
	for k,v in pairs(res) do
		local rule_key =  v

		-- Now look for this rule in the stage:access_check
		-- This is a O(1) retrieval of the rules for a given rule group
		local rule, err = red:hget("stage:content_check", rule_key)
		if (rule ~= ngx.null) then
			-- This is the rule to apply
			local m = ngx.re.match(body_data, rule)
			if m then
		        -----------------------------------------------------------------
		        -- The first one found will be blocked and we will skip the rest
		        -----------------------------------------------------------------
	        	return true, "Blocked : " .. rule_key 
	        end
		end
	end
	return false, "success"

end

function Ruleset:apply_access_filter(application, request_uri, getparams)
	-- Check all the rules that apply here for a given stage/group
	local red = Ruleset.connectRedis()
	
	local cjson = require "cjson"

	-- Check all the rules that belong to this group
	local res, flags = red:smembers(application .. ":" .. request_uri)
	for k,v in pairs(res) do
		local rule_key =  v

		-- Now look for this rule in the stage:access_check
		-- This is a O(1) retrieval of the rules for a given rule group
		local rule, err = red:hget("stage:access_check", rule_key)
		if (rule ~= ngx.null) then
			-- This is the rule to apply
			for p,q in pairs(getparams) do
				local m = ngx.re.match(q, rule)
	        	if m then
	        		-----------------------------------------------------------------
	        		-- The first one found will be blocked and we will skip the rest
	        		-----------------------------------------------------------------
	        		return true, "Blocked : " .. rule_key
	        	end
			end
		end
	end
	return false, "success"
end


return Ruleset
