local SipCreateMsg = require "voip.sip.message".new
local utils        = require "voip.sip.impl.utils"
local _gen_id	   = require 'voip.sip._gen_id'
local date         = require "date"

local format     = utils.format
local SipDigest  = utils.SipDigest

----------------------------------------------
local SIP_UA do

SIP_UA = {
  sip_patterns = {
    reg = SipCreateMsg{
      'REGISTER sip:%{SRVID}@%{SRVDOMAIN}:%{DOMAIN_PORT} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{USER}@%{DOMAIN}:%{DOMAIN_PORT}>',
      'From: <sip:%{USER}@%{DOMAIN}:%{DOMAIN_PORT}>;tag=%{TAG}',
      'Contact: <sip:%{USER}@%{HOST}:%{PORT}>;expires=60',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} REGISTER',
      'Date: %{DATE}',
      'User-Agent: LuaSIP',
      'Expires: 3600',
      'Max-Forwards: 70',
      'Content-Length: 0',
      ''
    };
    msg = SipCreateMsg{
      'MESSAGE sip:%{SRVID}@%{SRVDOMAIN} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{SRVID}@%{SRVDOMAIN}>',
      'From: <sip:%{USER}@%{DOMAIN}>;tag=%{TAG}',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} MESSAGE',
      'Date: %{DATE}',
      'Expires: 60',
      'Max-Forwards: 70',
      'Content-Length: 0',
      ''
    };
    hb = SipCreateMsg{
      'MESSAGE sip:%{SRVID}@%{SRVDOMAIN} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{SRVID}@%{SRVDOMAIN}>',
      'From: <sip:%{USER}@%{DOMAIN}>;tag=%{TAG}',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} MESSAGE',
      'Date: %{DATE}',
      'Expires: 60',
      'Max-Forwards: 70',
      'Content-Type: Application/MANSCDP+xml',
      'Content-Length: 149',
      '',
      '<?xml version="1.0"?>',
      '<Notify>',
      '<CmdType>Keepalive</CmdType>',
      '<SN>%{SN}</SN>',
      '<DeviceID>%{USER}</DeviceID>',
      '<Status>OK</Status>',
      '</Notify>',
    };
    invite = SipCreateMsg{
      'INVITE sip:%{SRVID}@%{SRVDOMAIN} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{SRVID}@%{SRVDOMAIN}>',
      'From: <sip:%{USER}@%{DOMAIN}>;tag=%{TAG}',
      'Contact: <sip:%{USER}@%{HOST}:%{PORT}>;expires=60',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} INVITE',
      'Date: %{DATE}',
      'Expires: 60',
      'Max-Forwards: 70',
      'Content-Length: 0',
      ''
    };
    info = SipCreateMsg {
      'INFO sip:%{SRVID}@%{SRVDOMAIN} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{SRVID}@%{SRVDOMAIN}>',
      'From: <sip:%{USER}@%{DOMAIN}>;tag=%{TAG}',
      'Contact: <sip:%{USER}@%{HOST}:%{PORT}>;expires=60',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} INFO',
      'Date: %{DATE}',
      'Expires: 60',
      'Max-Forwards: 70',
      'Content-Type: Application/MANSRTSP',
      'Content-Length: 0',
      ''
    };
    subscribe = SipCreateMsg {
      'SUBSCRIBE sip:%{SRVID}@%{SRVDOMAIN} SIP/2.0',
      'Via: SIP/2.0/UDP %{HOST}:%{PORT};branch=z9hG4bK%{BRANCH}',
      'To: <sip:%{SRVID}@%{SRVDOMAIN}>',
      'From: <sip:%{USER}@%{DOMAIN}>;tag=%{TAG}',
      'Contact: <sip:%{USER}@%{HOST}:%{PORT}>;expires=60',
      'Call-ID: %{CALLID}@%{HOST}',
      'CSeq: %{CSEQ} SUBSCRIBE',
      'Date: %{DATE}',
      'Expires: 60',
      'Max-Forwards: 70',
      'Content-Type: Application/MANSCDP+xml',
      'Content-Length: 0',
      ''
    };
  }
}

---
-- Create User Agent
-- @tparam string host localhost ip
-- @tparam number port local port used for connection
function SIP_UA:new(host, port, user, domain, srvid, srvdomain)
  assert(host and port and user and domain)-- and srvid and srvdomain)
  local t = setmetatable({
    private_ = {
      host = host,
      port = port,
      user = user,
      domain = domain,
      srvid = srvid or '<empty server id>',
      srvdomain = srvdomain or '<empty server domain>',
      gen = _gen_id();
    }
  },{__index=self})
  return t
end

function SIP_UA:init_param()
  return {
    HOST   = self.private_.host;
    PORT   = self.private_.port;

    DOMAIN      = self.private_.domain;
    DOMAIN_PORT = self.private_.port or 5060;
    USER        = self.private_.user or "anonymus";

    SRVID       = self.private_.srvid,
    SRVDOMAIN   = self.private_.srvdomain,

    CALLID = self.private_.gen.callid();
    BRANCH = self.private_.gen.branch();
    TAG    = self.private_.gen.tag();
    CSEQ   = self.private_.gen.cseq();
    DATE   = date():fmt('${rfc1123}');
  }
end

function SIP_UA:reg_impl()
  local PARAM       = self:init_param()

  local req = self.sip_patterns.reg:clone()
  req:applyParams(PARAM)

  return req
end

function SIP_UA:heart_beat(sn)
  assert(sn)
  local PARAM = self:init_param()
  PARAM.SN = sn
  local req = self.sip_patterns.hb:clone()
  req:applyParams(PARAM)

  return req
end

function SIP_UA:message(ctype, body, sid, sdomain)
  local PARAM = self:init_param()
  PARAM.SRVID = sid or PARAM.SRVID
  PARAM.SRVDOMAIN = sdomain or PARAM.SRVDOMAIN

  local req = self.sip_patterns.msg:clone()
  req:applyParams(PARAM)

  if ctype and body then
	  req:setContentBody(ctype, body)
  end

  return req
end

function SIP_UA:invite(ctype, body, sid, sdomain)
  local PARAM = self:init_param()
  PARAM.SRVID = sid or PARAM.SRVID
  PARAM.SRVDOMAIN = sdomain or PARAM.SRVDOMAIN
  local req = self.sip_patterns.invite:clone()
  req:applyParams(PARAM)
  if ctype and body then
	  req:setContentBody(ctype, body)
  end
  return req
end

function SIP_UA:info(ctype, body, sid, sdomain)
  local PARAM = self:init_param()
  PARAM.SRVID = sid or PARAM.SRVID
  PARAM.SRVDOMAIN = sdomain or PARAM.SRVDOMAIN
  local req = self.sip_patterns.info:clone()
  req:applyParams(PARAM)
  if ctype and body then
	  req:setContentBody(ctype, body)
  end
  return req
end

function SIP_UA:subscribe(ctype, body)
  local PARAM = self:init_param()
  local req = self.sip_patterns.subscribe:clone()
  req:applyParams(PARAM)
  if ctype and body then
	  req:setContentBody(ctype, body)
  end
  return req
end

function SIP_UA:authorize(req, resp, user, pass)
  local req = req:clone()
  if resp:getResponseCode() ~= 401 then
    return resp
  end

  local auth  = resp:getHeader("www-authenticate") or resp:getHeader("proxy-authenticate")
  if not auth then
    return nil, "No auth header in response"
  end

  local realm = string.match(auth, 'realm[ ]*=[ ]*"([^"]+)"')
  local nonce = string.match(auth, 'nonce[ ]*=[ ]*"([^"]+)"')
  local algo  = string.match(auth, 'algorithm[ ]*=[ ]*([^, ]+)') or 'MD5'
  if (not realm) or (not nonce) or (not algo) then
    return nil, "Unknown format auth header: " .. auth
  end

  local method, ruri, ver = req:getRequestLine()
  local auth_header = format([[Digest username="%{USER}",realm="%{REALM}",uri="%{RURI}",response="%{DIGEST}",nonce="%{NONCE}",algorithm=%{ALGO}]], {
    REALM  = realm;
    NONCE  = nonce;
    USER   = user or "anonymus";
    PWD    = pass or "";
    RURI   = ruri;
    ALGO   = algo or "MD5";
    -- @fixme use appropriate method INVITE/REGISTER
    DIGEST = SipDigest("REGISTER", algo, user or "anonymus", pass  or "", ruri, realm, nonce);
  })

  req:modifyHeader('Via', 'SIP/2.0/UDP '..self.private_.host..':'..self.private_.port..';branch=z9hG4bK'..self.private_.gen.branch())
  req:modifyHeader("CSeq", self.private_.gen.cseq() .. " " .. method)
  req:addHeader("Authorization", auth_header)

  return req
end

function SIP_UA:ping()
  return self:reg_impl()
end

function SIP_UA:reg()
  return self:reg_impl()
end

end
----------------------------------------------

local _M = {}

_M.new = function(...) return SIP_UA:new(...) end

return _M
