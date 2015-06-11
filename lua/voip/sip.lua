local SIP_MESSAGE    = require "voip.sip.message"
local SIP_UA         = require "voip.sip.ua"
local SIP_US         = require "voip.sip.us"

local _M = {}

function _M.new_message(...) return SIP_MESSAGE.new(...)   end

function _M.UA(...) return SIP_UA.new(...) end

function _M.US(...) return SIP_US.new(...) end

return _M
