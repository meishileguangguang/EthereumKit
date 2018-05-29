public enum Network {
    case eth
    case ropsten
    case `private`(chainID: Int)
	case btc

    
    // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    public var coinType: UInt32 {
        switch self {
        case .eth:
            return 60
		case .btc:
			return 0
        case .ropsten, .private:
            return 1
        }
    }
    
    public var privateKeyPrefix: UInt32 {
        switch self {
        case .eth, .btc:
            return 0x0488ade4
        case .ropsten, .private:
            return 0x04358394
        }
    }
    
    public var publicKeyPrefix: UInt32 {
        switch self {
        case .eth, .btc:
            return 0x0488b21e
        case .ropsten, .private:
            return 0x043587cf
        }
    }
    
    public var chainID: Int {
        switch self {
        case .eth:
            return 1
		case .btc:
			return 99 //瞎鸡巴写的,btc没有这个???
        case .ropsten:
            return 3
        case .private(let chainID):
            return chainID
        }
    }
}
