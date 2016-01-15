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
	resp:addHeader('Contact', '<sip:'..host..':'..port..'>')
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
	  resp:setContentBody("text/plain; charset=UTF-8", {"ERROR:", err})
  end
  --resp:addHeaderValueParameter("To",'tag', gen.tag())
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function Make488NotAcceptableHere(req, err)
  assert(req and err)
  local resp = sip_msg.new{
    "SIP/2.0 488 Not Acceptable Here";
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    "Content-Length: 0";
  }

  if err then
	  resp:setContentBody("text/plain; charset=UTF-8", {"ERROR:", err})
  end
  --resp:addHeaderValueParameter("To",'tag', gen.tag())
  assert(resp:getHeaderValueParameter('To', 'tag'))
  return resp
end

local function Make486BusyHere(req, err)
  assert(req and err)
  local resp = sip_msg.new{
    "SIP/2.0 486 Busy Here";
    "Via: "      .. req:getHeader('Via');
    "From: "     .. req:getHeader('From');
    "To: "       .. req:getHeader('To');
    "Call-ID: "  .. req:getHeader('Call-ID');
    "CSeq: "     .. req:getHeader('CSeq');
    "Content-Length: 0";
  }

  if err then
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


local function get_id_host_from_sip(msg)
	local _, uri = msg:getUri2('From')
	local id, host, port = ParseUri(uri)
	return id, host, port
end


local function MakeMSG(msg, ctype, body)
  local id, host = get_id_host_from_sip(msg)
  local cseq = msg:getCSeq()
  cseq = tostring(tonumber(cseq) + 1)
  local resp = sip_msg.new{
    "MESSAGE "      .. uri .. " SIP/2.0";
    "Via: "     .. req:getHeader('Via');
    "From: "    .. req:getHeader('To'); ---- Tag switch???
    "To: "      .. req:getHeader('From');
    "Call-ID: " .. req:getHeader('Call-ID');
    "CSeq: "    .. cseq .. ' Message';
    "Max-Forwards: 70";
    "Content-Length: 0";
  }
  assert(resp:getHeaderValueParameter('To', 'tag'))

  if ctype and body then
	  resp:setContentBody(ctype, body)
  end
  return resp
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

	Make486 = Make486BusyHere,
	Make486BusyHere = Make486BusyHere,

	Make488 = Make488NotAcceptableHere,
	Make488NotAcceptableHere = Make488NotAcceptableHere,

	Make500 = Make500InternalError,
	Make500InternalError = Make500InternalError,

	MakeACK = MakeACK,
	MakeBYE = MakeBYE,
	--- This make msg is for message during invite/dialog
	MakeMSG = MakeMSG,

	MakeFromResp = MakeFromResp,

	ParseUri = ParseUri,
}

