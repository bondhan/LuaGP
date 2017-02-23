Introduction
========
An implementation on GlobalPlatform on LUA 5.3

This library is an implementation of Global Platform to access GP card using LuA. The idea is to ease developer to access smartcard by using scripting, so that he can focus on the smart card itself not the programming language overhead. 

The dll of the compiled related function could be found [here](https://github.com/bondhan/LuaSmartCardLibrary)

This project is the integration of many libraries. Each source file belongs to its respective owner.

Installation
------------
* Download the root folder of LuaGP
* Download the LuA editor, in my case I only test using [ZeroBraneStudio] (https://studio.zerobrane.com/)
* Download the required dlls from LuaSmartCardLibray or you can compile from source, then copy the dlls to YourDriv:\\ZeroBraneStudioEduPack-xxx-win32\bin
  The dlls are: LuaSmartCardLibrary.dll, zip.dll, zlib1.dll
* Point the project root to LuaGP folder and try to execute some samples

Some Demo
------------
You can find in examples folder for some GP scripts and the output in the log folder accordingly

    * Authenticate with Card Manager

        gp.select_applet(CM_AID, card)
        gp.init_update(normal_key, host_random, apdu_mode, key_div, scp_mode, card)
        gp.external_authenticate(card)
    
    * Compute derived key from card ID
        sw, response = gp.init_update(normal_key, host_random, apdu_mode, key_div, scp_mode, card)
        local diversified_keyset = gp.diversify_key(gp.KEY_DIVERSIFY_MODE.EMV, response, normal_key)

    * Put new key
        gp.put_keyset(normal_key, card)
    
    * List existing applications inside the card
        gp.listCardContent(card)

License
------------
The MIT License (MIT)

Copyright (c) 2017 Bondhan Novandy

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

References
------------