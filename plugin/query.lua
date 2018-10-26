

local Object 	= require "classic.classic"
local ruleset   = require "ruleset"

local QueryView = Object:extend()

local style = "<body><head><style>table {font-family: arial, sans-serif;border-collapse: collapse;width: 100%;}td, th {border: 1px solid #dddddd;text-align: left;padding: 8px;}tr:nth-child(even) {background-color: #dddddd;}</style></head><body>"


function QueryView:new()
	-- Nothing for now
end


function string:split(delimiter)
	local result = { }
	local from  = 1
	local delim_from, delim_to = string.find( self, delimiter, from  )
	while delim_from do
	table.insert( result, string.sub( self, from , delim_from-1 ) )
	from  = delim_to + 1
	delim_from, delim_to = string.find( self, delimiter, from  )
	end
	table.insert( result, string.sub( self, from  ) )
	return result
end


function QueryView:showRule(query_string)
 	local ruleset = ruleset("")
    local params = query_string:split("=")
    local rulekey = (params[2])
    
    local category = ruleset:getRule(rulekey, "category")
    local title = ruleset:getRule(rulekey, "title")
    local description = ruleset:getRule(rulekey, "description")
    local applicable_stages = ruleset:getRuleApplicableStages(rulekey)
    ngx.say("<html>".. style .."<body>")
    ngx.say("<h2>Rule Information</h2>")
    ngx.say("<table><tr>")
    ngx.say("<th>Category</th>")
    ngx.say("<td>"..category.."</td>")
    ngx.say("</tr>")
    ngx.say("<tr>")
    ngx.say("<th>Title</th>")
    ngx.say("<td>"..title.."</td>")
    ngx.say("</tr>")
    ngx.say("<tr>")
    ngx.say("<th>Description</th>")
    ngx.say("<td>"..description.."</td>")
    ngx.say("</tr>")
    ngx.say("<tr>")
    ngx.say("<th>Applicable Stages</th>")
    ngx.say("<td>") 
    for k,v in pairs(applicable_stages) do
        ngx.say(k .. " : " .. v .. "<BR>")
    end
    ngx.say("</td>")
    ngx.say("</tr>")
    ngx.say("</table>")

    ngx.say("<table>")
    ngx.say("<BR><BR>")

end


function QueryView:showRoutes()
	local ruleset = ruleset("")
	application = ruleset:getBalancerInfo('balancer:2', 'application')
	host = ruleset:getBalancerInfo('balancer:2', 'host')
	port = ruleset:getBalancerInfo('balancer:2', 'port')
	local routes = ruleset:getRoutes("application:"..application)

	ngx.say("<html>".. style .."<body>")
	ngx.say("<h2>Application Details</h2>")
	ngx.say("<table><tr>")
	ngx.say("<th>Application</th>")
	ngx.say("<td>"..application.."</td>")
	ngx.say("</tr>")
	ngx.say("<tr>")
	ngx.say("<th>Host</th>")
	ngx.say("<td>"..host.."</td>")
	ngx.say("</tr>")
	ngx.say("<tr>")
	ngx.say("<th>Port</th>")
	ngx.say("<td>"..port.."</td>")
	ngx.say("</tr>")
	ngx.say("</table>")

	ngx.say("<table>")
	ngx.say("<BR><BR>")


	ngx.say("<tr><th>Routes</th><th>Rules</th></tr>")
	for k,v in pairs(routes) do
	local rules = ruleset:getRules("application:"..application, v)

	ngx.say("<tr><td>".. v .. "</td>")
	ngx.say("<td>")
	for k1,v1 in pairs(rules) do
	    ngx.say("<A HREF=showrule?rule=".. v1 .. ">"  ..  v1.."</A></BR>")
	end
	ngx.say("</td>")
	ngx.say("</tr>")
	end
	ngx.say("</table><body></html>")


end


return QueryView

