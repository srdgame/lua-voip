local utils = require 'voip.sip.impl.utils'

local generators = utils.generators

local gen = function() 
	return {
		branch = generators.random(11);
		tag    = generators.random(10);
		nonce  = generators.random(32);
		callid = generators.uuid();
		cseq   = generators.sequence(0);
	}
end

return gen
