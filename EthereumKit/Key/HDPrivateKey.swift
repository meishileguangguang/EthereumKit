import CryptoEthereumSwift
import CryptoSwift

public struct HDPrivateKey {
    public let raw: Data
    public let chainCode: Data
    private let depth: UInt8
    private let fingerprint: UInt32
    private let childIndex: UInt32
	public var network = Network.ropsten
	
	public init?(password: String) {
		let userDefauts = UserDefaults.standard
		
		
		
		let salt = "Ut3Opm78U76VbwoP4Vx6UdfN234Esaz9"
		let pbkdf2Password = try! PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes,
									   keyLength: 16).calculate()
		
		let readPbkdf2Password = userDefauts.string(forKey: "pbkdf2Password")

		if pbkdf2Password.toHexString() != readPbkdf2Password {
			
			return nil
		}
		
		let hdPrivateKeyRaw = userDefauts.data(forKey: "HDPrivateKeyRaw")
		self.raw = HDPrivateKey.Decode_AES(dataToDecode: hdPrivateKeyRaw!, key: pbkdf2Password)
		let hdPrivateKeyChainCode = userDefauts.data(forKey: "HDPrivateKeyChainCode")
		self.chainCode = HDPrivateKey.Decode_AES(dataToDecode: hdPrivateKeyChainCode!, key: pbkdf2Password)
		self.depth = 0
		self.fingerprint = 0
		self.childIndex = 0
	}
	
	public init(seed: Data) {
		let output = Crypto.HMACSHA512(key: "Bitcoin seed".data(using: .ascii)!, data: seed)
		self.raw = output[0..<32]
		self.chainCode = output[32..<64]
		self.depth = 0
		self.fingerprint = 0
		self.childIndex = 0
	}
	
    public init(seed: Data, network: Network) {
        let output = Crypto.HMACSHA512(key: "Bitcoin seed".data(using: .ascii)!, data: seed)
        self.raw = output[0..<32]
        self.chainCode = output[32..<64]
        self.depth = 0
        self.fingerprint = 0
        self.childIndex = 0
        self.network = network
    }
    
    private init(hdPrivateKey: Data, chainCode: Data, depth: UInt8, fingerprint: UInt32, index: UInt32, network: Network) {
        self.raw = hdPrivateKey
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = index
        self.network = network
    }
	
	public func save(password: String) {
		
		let salt = "Ut3Opm78U76VbwoP4Vx6UdfN234Esaz9"
		let pbkdf2Password = try! PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes,
									   keyLength: 16).calculate()
		
		let userDefauts = UserDefaults.standard
		userDefauts.setValue(pbkdf2Password.toHexString(), forKey: "pbkdf2Password")

		let hdPrivateKeyRaw = endcode_AES(dataToEncode: raw, key: pbkdf2Password)
		userDefauts.set(hdPrivateKeyRaw, forKey: "HDPrivateKeyRaw")
		let hdPrivateKeyChainCode = endcode_AES(dataToEncode: chainCode, key: pbkdf2Password)
		userDefauts.set(hdPrivateKeyChainCode, forKey: "HDPrivateKeyChainCode")
	}
    
    public func privateKey() -> PrivateKey {
        return PrivateKey(raw: Data(hex: "0x") + raw)
    }
    
    public func hdPublicKey() -> HDPublicKey {
        return HDPublicKey(hdPrivateKey: self, chainCode: chainCode, network: network, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
    }
    
    public func extended() -> String {
        var extendedPrivateKeyData = Data()
        extendedPrivateKeyData += network.privateKeyPrefix.bigEndian
        extendedPrivateKeyData += depth.littleEndian
        extendedPrivateKeyData += fingerprint.littleEndian
        extendedPrivateKeyData += childIndex.littleEndian
        extendedPrivateKeyData += chainCode
        extendedPrivateKeyData += UInt8(0)
        extendedPrivateKeyData += raw
        let checksum = Crypto.doubleSHA256(extendedPrivateKeyData).prefix(4)
        return Base58.encode(extendedPrivateKeyData + checksum)
    }
    
    internal func derived(at index: UInt32, hardens: Bool = false) throws -> HDPrivateKey {
        guard (0x80000000 & index) == 0 else {
            fatalError("Invalid index \(index)")
        }
        
        let keyDeriver = KeyDerivation(
            privateKey: raw,
            publicKey: hdPublicKey().raw,
            chainCode: chainCode,
            depth: depth,
            fingerprint: fingerprint,
            childIndex: childIndex
        )
        
        guard let derivedKey = keyDeriver.derived(at: index, hardened: hardens) else {
            throw EthereumKitError.cryptoError(.keyDerivateionFailed)
        }
        
        return HDPrivateKey(
            hdPrivateKey: derivedKey.privateKey!,
            chainCode: derivedKey.chainCode,
            depth: derivedKey.depth,
            fingerprint: derivedKey.fingerprint,
            index: derivedKey.childIndex,
            network: network
        )
    }
}

extension HDPrivateKey {
	
	private func endcode_AES(dataToEncode: Data, key: [UInt8]) -> Data {
		var result: [UInt8] = []
		do {
			let aes = try AES(key: Padding.zeroPadding.add(to: key, blockSize: AES.blockSize), blockMode: .ECB)
			result = try aes.encrypt(dataToEncode.bytes)
		} catch { }
		
		let data = Data(bytes: result)
		
		return data
	}
	
	//  MARK:  AES-128解密
	private static func Decode_AES(dataToDecode: Data, key: [UInt8]) -> Data {
		// decode AES
		var decrypted: [UInt8] = []
		do {
			let aes = try AES(key: Padding.zeroPadding.add(to: key, blockSize: AES.blockSize), blockMode: .ECB)

			decrypted = try aes.decrypt(dataToDecode.bytes)
		} catch {
			
		}
		// byte 转换成NSData
		let data = Data(decrypted)
		
		return data
	}
}
