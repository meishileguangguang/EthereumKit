public final class HDWallet {
    
    private let masterPrivateKey: HDPrivateKey
    private let network: Network
    
    public init(seed: Data, network: Network) {
        self.masterPrivateKey = HDPrivateKey(seed: seed, network: network)
        self.network = network
    }
    
    // MARK: - Public Methods

    public func generatePrivateKey(at index: UInt32) throws -> PrivateKey {
        return try privateKey(change: .external).derived(at: index).privateKey()
    }
    
    public func generateAddress(at index: UInt32) throws -> String {
        return try generatePrivateKey(at: index).publicKey.generateAddress()
    }
    
    public func dumpPrivateKey(at index: UInt32) throws -> String {
        return try generatePrivateKey(at: index).raw.toHexString()
    }
	
	
	/// Sign signs rlp encoding hash of specified raw transaction
	///
	/// - Parameter rawTransaction: raw transaction to hash
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(rawTransaction: RawTransaction) throws -> String {
		let signer = EIP155Signer(chainID: network.chainID)
		
		let privateKey = try! generatePrivateKey(at: 0)
		let rawData = try signer.sign(rawTransaction, privateKey: privateKey)
		let hash = rawData.toHexString().addHexPrefix()
		
		return hash
	}
	
	/// Sign calculates an Ethereum ECDSA signature for: keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
	/// See also: https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
	///
	/// - Parameter hex: message in hex format to sign
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(hex: String) throws -> String {
		let prefix = "\u{19}Ethereum Signed Message:\n"
		
		let messageData = Data(hex: hex.stripHexPrefix())
		
		guard let prefixData = (prefix + String(messageData.count)).data(using: .ascii) else {
			throw EthereumKitError.cryptoError(.failedToEncode(prefix + String(messageData.count)))
		}
		
		let hash = Crypto.hashSHA3_256(prefixData + messageData)
		
		let privateKey = try! generatePrivateKey(at: 0)
		var signiture = try privateKey.sign(hash: hash)
		
		// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
		// where the V value will be 27 or 28 for legacy reasons.
		signiture[64] += 27
		
		let signedHash = signiture.toHexString().addHexPrefix()
		
		return signedHash
	}
	
	/// Sign calculates an Ethereum ECDSA signature for: keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
	/// See also: https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
	///
	/// - Parameter hex: message to sign
	/// - Returns: signiture in hex format
	/// - Throws: EthereumKitError.failedToEncode when failed to encode
	public func signEth(message: String) throws -> String {
		return try signEth(hex: message.toHexString())
	}
	
    
    // MARK: - Private Methods
    
    // Ethereum only uses external.
    private enum Change: UInt32 {
        case external = 0
        case `internal` = 1
    }
    
    // m/44'/coin_type'/0'/external
    private func privateKey(change: Change) throws -> HDPrivateKey {
        return try masterPrivateKey
            .derived(at: 44, hardens: true)
            .derived(at: network.coinType, hardens: true)
            .derived(at: 0, hardens: true)
            .derived(at: change.rawValue)
    }
}
