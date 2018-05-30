//
//  ViewController.swift
//  Example
//
//  Created by yuzushioh on 2018/01/01.
//  Copyright © 2018 yuzushioh. All rights reserved.
//

import UIKit
import EthereumKit
import CryptoSwift

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
		
		createHDWallet()
    }
	
	private func testWallet () {
		// It generates an array of random mnemonic words. Use it for back-ups.
		// You can specify which language to use for the sentence by second parameter.
		let mnemonic = Mnemonic.create(entropy: Data(hex: "000102030405060708090a0b0c0d0e0f"))
		
		// Then generate seed data from the mnemonic sentence.
		// You can set password for more secure seed data.
		let seed = Mnemonic.createSeed(mnemonic: mnemonic)
		
		// Create wallet by passing seed data and which network you want to connect.
		// for network, EthereumKit currently supports mainnet and ropsten.
		let wallet: Wallet
		do {
			wallet = try Wallet(seed: seed, network: .ropsten, debugPrints: true)
		} catch let error {
			fatalError("Error: \(error.localizedDescription)")
		}
		
		// Generate an address, or private key by simply calling
		let address = wallet.generateAddress()
		
		// Create an instance of `Geth` with `Configuration`.
		// In configuration, specify
		// - network: network to use
		// - nodeEndpoint: url for the node you want to connect
		// - etherscanAPIKey: api key of etherscan
		let configuration = Configuration(
			network: .ropsten,
			nodeEndpoint: "https://ropsten.infura.io/z1sEfnzz0LLMsdYMX4PV",
			etherscanAPIKey: "XE7QVJNVMKJT75ATEPY1HPWTPYCVCKMMJ7",
			debugPrints: true
		)
		
		let geth = Geth(configuration: configuration)
		
		// To get a balance of an address, call `getBalance`.
		geth.getBalance(of: address) { _ in }
		
		// You can get the current nonce by calling
		geth.getTransactionCount(of: address) { result in
			switch result {
			case .success(let nonce):
				let rawTransaction = RawTransaction(ether: "0.0001", to: address, gasPrice: Converter.toWei(GWei: 10), gasLimit: 21000, nonce: nonce)
				let tx: String
				do {
					tx = try wallet.sign(rawTransaction: rawTransaction)
				} catch let error {
					fatalError("Error: \(error.localizedDescription)")
				}
				
				// It returns the transaction ID.
				geth.sendRawTransaction(rawTransaction: tx) { _ in }
				
			case .failure(let error):
				print("Error: \(error.localizedDescription)")
			}
		}
	}
}

extension ViewController {
	//HDWallet
	
	func createHDWallet() {
		
		let m = UserDefaults.standard.array(forKey: "mnemonics")
		
		if m != nil {
			
			getHDWallet()
			
			return
		}
		
		//加密密码后,保存HDWallet的mastPrivateKey到本地
		
		
		let password = "123456"

		let mnemonics = Mnemonic.create()
		
		let seed = Mnemonic.createSeed(mnemonic: mnemonics)
		
		let wallet = HDWallet(seed: seed, network: .ropsten)
		
		let address = try! wallet.generateAddress(at: 0)
		
		print("createHDWallet create address:" + address)
		
		wallet.saveMasterPrivateKey(password: password)
		
		UserDefaults.standard.set(mnemonics, forKey: "mnemonics")

	}

	func getHDWallet() {
		let password = "1234222256"

		if let wallet = HDWallet(password: password) {
			let address = try! wallet.generateAddress(at: 0)
			print("getHDWallet create address:" + address)
		}else{
			print("密码错误!!!")
		}

		
		
	}

}
