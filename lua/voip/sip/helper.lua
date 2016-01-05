---
-- Hepler functions for building message
--

local sip_msg = require 'voip.sip.message'
local gen = require 'voip.sip._gen_id'

local function Make100Trying(req)
  local resp = sip_msg.new{
    "SIP/2.0 100 Trying";
    "Via: "     .. req:getHeader('Via');
    "From: "    .. req:getHeader('From');
    "To: "      .. req:getHeader('To');
    "Call-ID: " .. req:getHeader('Call-ID');
    "CSeq: "    .. req:getHeader('CSeq');
    "Content-Length: 0";
  }
  return resp
end

local function Make200OK(req, host, port)
  local resp = sip_msg.new{
    "SIP/2.0 200 OK";
    "Via: "     .. req:getHeader('Via');
    "From: "    .. req:getHeader('From');
    "To: "      .. req:getHeader('To');
    "Call-ID: " .. req:getHeader('Call-ID');
    "CSeq: "    .. req:getHeader('CSeq');
    --"Expires: " .. (req:getHeader('Expires') or '60');
    "Content-Length: 0";
  }
  assert(resp:getHeaderValueParameter('To', 'tag'))
  if host and port then
	resp:setHeader('Contact', '<sip:'..host..'@'..port..'>')
  end
  return resp
end

local function Make401Unauthorized(req, realm)
  assert(realm)
  local resp = sip_msg.new{
    "SIP/2.0 401 Unauthorized";
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    'WWW-Authenticate: Digest realm="' .. realm .. '",nonce="' .. gen.nonce() .. '",algorithm=MD5';
    "Content-Length: 0";
  }
  --resp:addHeaderValueParameter("To",'tag', gen.tag())
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function Make403Forbidden(req, err)
  local resp = sip_msg.new{
    "SIP/2.0 403 Forbidden";
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    "Content-Length: 0";
  }
  if err then
	  --resp:addHeader("Error-Info", err)
	  resp:setContentBody("text/plain; charset=UTF-8", {"ERROR:", err})
  end
  --resp:addHeaderValueParameter("To",'tag', gen.tag())
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function Make500InternalError(req, err)
  local resp = sip_msg.new{
    "SIP/2.0 500 Server Internal Error";
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    "Content-Length: 0";
  }
  if err then
	  --resp:addHeader("Error-Info", err)
	  resp:setContentBody("text/plain; charset=UTF-8", {"ERROR:", err})
  end
  --resp:addHeaderValueParameter("To",'tag', gen.tag())
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp

end

local function MakeFromResp(req, resp)
  local msg = sip_msg.new{
    resp[1];
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    "Content-Length: 0";
  }
  return msg
end

local function MakeACK(req, to_tag)
  local m, uri, ver = req:getRequestLine()
  assert(m == 'INVITE')
  local cseq = req:getCSeq()
  local resp = sip_msg.new{
    "ACK "      .. uri .. " " .. ver;
    "Via: "     .. req:getHeader('Via');
    "From: "    .. req:getHeader('From');
    "To: "      .. req:getHeader('To');
    "Call-ID: " .. req:getHeader('Call-ID');
    "CSeq: "    .. cseq .. ' ACK';
    "Max-Forwards: 70";
    "Content-Length: 0";
  }
  if to_tag then
    resp:addHeaderValueParameter("To",'tag', to_tag)
  end
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function MakeBYE(req, to_tag)
  local m, uri, ver = req:getRequestLine()
  assert(m == 'INVITE')
  local cseq = req:getCSeq()
  cseq = tostring(tonumber(cseq) + 1)
  local resp = sip_msg.new{
    "BYE "      .. uri .. " " .. ver;
    "Via: "     .. req:getHeader('Via');
    "From: "    .. req:getHeader('From');
    "To: "      .. req:getHeader('To');
    "Call-ID: " .. req:getHeader('Call-ID');
    "CSeq: "    .. cseq .. ' BYE';
    "Max-Forwards: 70";
    "Content-Length: 0";
  }
  if to_tag then
    resp:addHeaderValueParameter("To",'tag', to_tag)
  end
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function ParseUri(uri)
	if string.lower(uri:sub(1, 4)) == 'sip:' then
		uri = uri:sub(5)
	end
	local id, host = uri:match('^([^@]+)@([^:]+)')
	local port = uri:match(':([0-9]+)')
	return id, host, port
end

return {
	Make100 = Make100Trying,
	Make100Trying = Make100Trying,

	Make200 = Make200OK,
	Make200OK = Make200OK,

	Make401 = Make401Unauthorized,
	Make401Unauthorized = Make401Unauthorized,

	Make403 = Make403Forbidden,
	Make403Forbidden = Make403Forbidden,

	Make500 = Make500InternalError,
	Make500InternalError = Make500InternalError,

	MakeACK = MakeACK,
	MakeBYE = MakeBYE,

	MakeFromResp = MakeFromResp,

	ParseUri = ParseUri,
}

