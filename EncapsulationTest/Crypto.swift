//
//  Crypto.swift
//  EncapsulationTest
//
//  Created by RadCns_SON_JIYOUNG on 2023/11/23.
//

import Foundation
import CommonCrypto


struct IRISCrypto {
    
    enum CryptoError: Error {
        case cryptoFailed(status: CCCryptorStatus)
        case badKeyLength
    }
    
    private var key: Data
    
    init(baseKey: String) {
        guard let keyData = baseKey.data(using: .utf8),
              keyData.count == kCCKeySizeAES256
        else
        {
            self.key = Data()
            return
        }
        
        self.key = keyData
    }
    
    func AES256Encrypt(value: String?) -> String? {
        guard let data = value?.data(using: .utf8) else { return nil }
        return crypto(data: data, operation: CCOperation(kCCEncrypt))?.base64EncodedString()
    }

    func AES256Decrypt(value: String?) -> String? {
        guard let str = value, let data = Data(base64Encoded: str),
              let decryptData = crypto(data: data, operation: CCOperation(kCCDecrypt))
        else { return nil }
        return String(data: decryptData, encoding: .utf8)
    }
    
    private func crypto(data: Data, operation: CCOperation) -> Data? {
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        
        data.withUnsafeBytes { (encryptedBytes: UnsafePointer<UInt8>!) -> () in
            key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>!) -> () in
                status = CCCrypt(operation,
                                 CCAlgorithm(kCCAlgorithmAES128),
                                 CCOperation(kCCOptionPKCS7Padding),
                                 keyBytes,
                                 key.count,
                                 nil,
                                 encryptedBytes,
                                 data.count,
                                 &outBytes,
                                 outBytes.count,
                                 &outLength)
            }
        }
        
        guard status == kCCSuccess else { return nil }
        
        return Data(bytes: UnsafePointer<UInt8>(outBytes), count: outLength)
    }
}
