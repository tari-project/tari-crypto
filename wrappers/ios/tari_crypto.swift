/**
 * Copyright 2021 The Tari Project
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of
 * its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import Foundation

enum Errors: Error {
    case generic(_ errorCode: Int32)
}

class TariCrypto {

    public func getVersion() -> String {
        return String(cString: version())
    }

    public func lookupError(code: Int32) -> String {
        // FFI interface needs to change, there is a safer and simpler way to do this
        let length: Int32 = 129 // This can be eliminated, see below comment and conversion after that
        var buffer: [Int8] = [Int8](repeating: 0, count: Int(length)) // Allocation/Deallocation should be kept on the same side of the boundary, only pointers and primitive types should cross, furthermore memory alignment is not guaranteed via FFI
        lookup_error_message(code, &buffer, length) // Buffer length is returned by function at the end, should return 0 according to the header
        let string = String(cString: buffer)
        return string
    }

    public func randomKeyPair() -> (KeyArray, KeyArray) {
        // FFI interface needs to change, this can be done cleaner (C arrays are imported in swift as arrays of tuples, not values)
        var sk: KeyArray = (UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                            UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                            UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0))
        var pk: KeyArray = (UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                            UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                            UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0))
        random_keypair(&sk,&pk) // Int should come out as an inout parameter rather than a return value for clarity (see verify() method in header), method need not have a return value (i.e void)
        return (sk,pk)
    }

    public func signMessage(sk: KeyArray, msg: String) throws -> (KeyArray,KeyArray) {
        // FFI interface needs to change, this can be done cleaner (C arrays are imported in swift as arrays of tuples, not values)
        var signature: KeyArray = (UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                             UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                             UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0))
        var nonce: KeyArray = (UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                             UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),
                             UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0),UInt8(0))
        var secret = sk
        let msgPtr = (msg as NSString).utf8String
        let result = sign(&secret,msgPtr,&nonce,&signature) // Int should come out as an inout parameter rather than a return value for clarity (see verify() method in header), method need not have a return value (i.e void)
        guard result == 0 else {
            throw Errors.generic(result)
        }
        return (signature,nonce)
    }

    public func verifyMessage(pk: KeyArray, msg: String, nonce: KeyArray, signature: KeyArray) throws -> Bool {
        // Note on FFI interface, errorCode seems unnecessary for this function, could purely just be a boolean
        var errorCode: Int32 = 0
        let msgPtr = (msg as NSString).utf8String
        var p = pk
        var n = nonce
        var s = signature
        let result = verify(&p,msgPtr,&n,&s,&errorCode)
        guard errorCode == 0 else {
            throw Errors.generic(errorCode)
        }
        return result
    }
}
