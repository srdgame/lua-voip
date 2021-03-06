local SipCreateMsg = require "voip.sip.message".new
local utils        = require "voip.sip.impl.utils"
local _gen_id	   = require 'voip.sip._gen_id'

local format     = utils.format
local SipDigest  = utils.SipDigest

----------------------------------------------
local SIP_US do

SIP_US = {}

function SIP_US:new(host, port, user, domain)
  assert(host and port)
  local t = setmetatable({
    private_ = {
      gen = _gen_id();
      host = host;
      port = port;
      user = user;
      domain = domain;
    }
  },{__index=self})
  return t
end

function SIP_US:check_auth_response(req, user, pass)
  local auth  = req:getHeader("Authorization")
  if not auth then return false end

  local user 	 = user or string.match(auth, 'username[ ]*=[ ]*"([^"]+)"')
  local realm    = string.match(auth, 'realm[ ]*=[ ]*"([^"]+)"')
  local uri      = string.match(auth, 'uri[ ]*=[ ]*"([^"]+)"')
  local response = string.match(auth, 'response[ ]*=[ ]*"([^"]+)"')
  local realm    = string.match(auth, 'realm[ ]*=[ ]*"([^"]+)"')
  local nonce    = string.match(auth, 'nonce[ ]*=[ ]*"([^"]+)"')
  local algo     = string.match(auth, 'algorithm[ ]*=[ ]*([^, ]+)')
  if (not realm) or (not nonce) or (not algo) or (not uri) or (not response) or (not nonce) then
    return nil, "Unknown format auth header"
  end
  local DIGEST = SipDigest("REGISTER", algo, user or "anonymus", pass  or "", uri, realm, nonce);
  --print(DIGEST, response, DIGEST==response)
  return DIGEST == response, user
end

function SIP_US:proxy_invite(req)
	local msg = req:clone()
      	--'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
	msg:modifyHeader('Via', "SIP/2.0/UDP "..self.private_.host..":"..self.private_.port..";branch=z9hG4bK"..self.private_.gen.branch())
      	--'From: <sip:%{USER}@%{DOMAIN}:%{DOMAIN_PORT}>;tag=%{TAG}',
	msg:modifyHeader('From', "<sip:"..self.private_.user.."@"..self.private_.domain..":"..self.private_.port..">;tag="..self.private_.gen.tag())
	msg:removeHeaderValue('To', 'tag')
      	-- 'Call-ID: %{CALLID}@%{HOST}',
	msg:modifyHeader('Call-ID', self.private_.gen.callid().."@"..self.private_.host)
	-- 'Contact: <sip:%{USER}@%{HOST}:%{PORT}>;expires=60',
	msg:modifyHeader('Concat', "<sip:"..self.private_.user.."@"..self.private_.host..":"..self.private_.port..">;expires=60")
	-- msg:modifyHeader('Max-Forwards', tonumber(msg:getHeader('Max-Forwards') - 1))
	msg:modifyHeader('User-Agent', "LuaSIP")
	local no, method = req:getCSeq()
	req:modifyHeader("CSeq", self.private_.gen.cseq() .. " " .. method)
	return msg
end

function SIP_US:proxy_invite_response(resp, req)
	local msg = resp:clone()
	msg:modifyHeader('Via', req:getHeader('Via'))
	msg:modifyHeader('From', req:getHeader('From'))
	msg:modifyHeader('To', req:getHeader('To'))
	msg:modifyHeader('Call-ID', req:getHeader('Call-ID'))
	msg:modifyHeader('CSeq', req:getHeader('CSeq'))
	return msg
end

function SIP_US:proxy_message(req)
	local msg = req:clone()
	msg:modifyHeader('Via', "SIP/2.0/UDP "..self.private_.host..":"..self.private_.port..";branch=z9hG4bK"..self.private_.gen.branch())
	msg:modifyHeader('Call-ID', self.private_.gen.callid().."@"..self.private_.host)
	msg:modifyHeader('Concat', "<sip:"..self.private_.user.."@"..self.private_.host..":"..self.private_.port..">;expires=60")
	msg:modifyHeader('User-Agent', "LuaSIP")
	return msg
end

end
----------------------------------------------

local _M = {}

_M.new = function(...) return SIP_US:new(...) end

return _M

