local utils = require 'voip.sip.impl.utils'

local generators = utils.generators

local gen ={
        branch = generators.random(11);
        tag    = generators.random(10);
        nonce  = generators.random(32);
        callid = generators.uuid();
        cseq   = generators.sequence(0);
}

return gen
